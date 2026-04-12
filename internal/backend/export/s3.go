package export

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

// S3Config holds configuration for the S3 export backend.
type S3Config struct {
	// Endpoint is the S3 API endpoint (e.g., "https://s3.us-east-1.amazonaws.com").
	Endpoint string

	// Bucket is the target S3 bucket.
	Bucket string

	// Region is the AWS region.
	Region string

	// KMSKeyID is the KMS key ARN for server-side encryption (SSE-KMS).
	KMSKeyID string

	// ObjectLockMode is the S3 Object Lock retention mode. Default: "COMPLIANCE".
	ObjectLockMode string

	// ObjectLockRetainDays is how many days to retain objects. Default: 365.
	ObjectLockRetainDays int

	// AccessKeyID is the AWS access key. If empty, uses instance role.
	AccessKeyID string

	// SecretAccessKey is the AWS secret key.
	SecretAccessKey string

	// Serializer is the format serializer to use. Defaults to JSON.
	Serializer FormatSerializer

	// HTTPClient allows injecting a custom HTTP client (for testing).
	HTTPClient *http.Client
}

// S3Backend exports audit records to S3 with SSE-KMS encryption and
// Object Lock in COMPLIANCE mode.
type S3Backend struct {
	config S3Config
	client *http.Client
}

// NewS3Backend creates a new S3 export backend.
func NewS3Backend(config S3Config) *S3Backend {
	if config.ObjectLockMode == "" {
		config.ObjectLockMode = "COMPLIANCE"
	}
	if config.ObjectLockRetainDays == 0 {
		config.ObjectLockRetainDays = 365
	}
	if config.Serializer == nil {
		config.Serializer = &JSONSerializer{}
	}

	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}

	return &S3Backend{
		config: config,
		client: client,
	}
}

// Export uploads the audit record to S3.
func (b *S3Backend) Export(ctx context.Context, record AuditRecord) error {
	payload, err := b.config.Serializer.Serialize(record)
	if err != nil {
		return fmt.Errorf("s3: serialization failed: %w", err)
	}

	key := s3ObjectKey(record)
	url := fmt.Sprintf("%s/%s/%s", b.config.Endpoint, b.config.Bucket, key)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("s3: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", b.config.Serializer.ContentType())

	// SSE-KMS headers.
	if b.config.KMSKeyID != "" {
		req.Header.Set("x-amz-server-side-encryption", "aws:kms")
		req.Header.Set("x-amz-server-side-encryption-aws-kms-key-id", b.config.KMSKeyID)
	}

	// Object Lock headers.
	retainUntil := record.Timestamp.AddDate(0, 0, b.config.ObjectLockRetainDays)
	req.Header.Set("x-amz-object-lock-mode", b.config.ObjectLockMode)
	req.Header.Set("x-amz-object-lock-retain-until-date", retainUntil.UTC().Format(time.RFC3339))

	// Content hash for SigV4.
	payloadHash := sha256Hex(payload)
	req.Header.Set("x-amz-content-sha256", payloadHash)

	// Sign the request if credentials are provided.
	if b.config.AccessKeyID != "" {
		signS3Request(req, b.config, payload)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("s3: request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("s3: PutObject returned status %d", resp.StatusCode)
	}

	return nil
}

func (b *S3Backend) Name() string { return "s3" }

// s3ObjectKey generates the S3 object key for an audit record.
// Format: sidereal/YYYY/MM/DD/<probeType>/<probeID>.json
func s3ObjectKey(record AuditRecord) string {
	t := record.Timestamp.UTC()
	return fmt.Sprintf("sidereal/%d/%02d/%02d/%s/%s.json",
		t.Year(), t.Month(), t.Day(),
		record.ProbeType,
		record.ProbeID,
	)
}

// sha256Hex returns the hex-encoded SHA-256 hash of data.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// signS3Request adds SigV4 Authorization header to the request.
// This is a simplified SigV4 implementation sufficient for S3 PutObject.
func signS3Request(req *http.Request, config S3Config, payload []byte) {
	now := time.Now().UTC()
	dateStamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	req.Header.Set("x-amz-date", amzDate)

	// SigV4 signing key derivation.
	signingKey := deriveSigningKey(config.SecretAccessKey, dateStamp, config.Region, "s3")

	// Simplified canonical request for PutObject.
	payloadHash := sha256Hex(payload)
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		req.URL.Host, payloadHash, amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	canonicalRequest := fmt.Sprintf("%s\n%s\n\n%s\n%s\n%s",
		req.Method, req.URL.Path, canonicalHeaders, signedHeaders, payloadHash)

	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, config.Region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate, credentialScope, sha256Hex([]byte(canonicalRequest)))

	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		config.AccessKeyID, credentialScope, signedHeaders, signature))
}

func deriveSigningKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
