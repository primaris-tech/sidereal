package export

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Splunk ---

func TestSplunkBackend_Export(t *testing.T) {
	var receivedAuth string
	var receivedBody string

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer server.Close()

	backend := NewSplunkBackend(SplunkConfig{
		Endpoint: server.URL,
		Token:    "test-hec-token",
		Index:    "sidereal",
	})
	backend.client = server.Client()

	err := backend.Export(context.Background(), testRecord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedAuth != "Splunk test-hec-token" {
		t.Errorf("expected Splunk auth header, got %q", receivedAuth)
	}
	if !strings.Contains(receivedBody, "probe-abc-123") {
		t.Error("request body missing probeId")
	}
	if backend.Name() != "splunk" {
		t.Errorf("expected name 'splunk', got %q", backend.Name())
	}
}

func TestSplunkBackend_ServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	backend := NewSplunkBackend(SplunkConfig{
		Endpoint: server.URL,
		Token:    "token",
	})
	backend.client = server.Client()

	err := backend.Export(context.Background(), testRecord)
	if err == nil {
		t.Error("expected error for 503 response")
	}
}

// --- Elasticsearch ---

func TestElasticsearchBackend_Export(t *testing.T) {
	var receivedPath string
	var receivedAuth string

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"result":"created"}`))
	}))
	defer server.Close()

	backend := NewElasticsearchBackend(ElasticsearchConfig{
		Endpoint: server.URL,
		Index:    "sidereal-results",
		APIKey:   "test-api-key",
	})
	backend.client = server.Client()

	err := backend.Export(context.Background(), testRecord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedPath := "/sidereal-results/_doc/probe-abc-123"
	if receivedPath != expectedPath {
		t.Errorf("expected path %q, got %q", expectedPath, receivedPath)
	}
	if receivedAuth != "ApiKey test-api-key" {
		t.Errorf("expected ApiKey auth, got %q", receivedAuth)
	}
	if backend.Name() != "elasticsearch" {
		t.Errorf("expected name 'elasticsearch', got %q", backend.Name())
	}
}

func TestElasticsearchBackend_ServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	backend := NewElasticsearchBackend(ElasticsearchConfig{
		Endpoint: server.URL,
	})
	backend.client = server.Client()

	err := backend.Export(context.Background(), testRecord)
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

// --- S3 ---

func TestS3Backend_Export(t *testing.T) {
	var receivedPath string
	var receivedSSE string
	var receivedLockMode string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedSSE = r.Header.Get("x-amz-server-side-encryption")
		receivedLockMode = r.Header.Get("x-amz-object-lock-mode")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	backend := NewS3Backend(S3Config{
		Endpoint:   server.URL,
		Bucket:     "audit-bucket",
		Region:     "us-east-1",
		KMSKeyID:   "arn:aws:kms:us-east-1:123456789:key/test-key",
		HTTPClient: server.Client(),
	})

	err := backend.Export(context.Background(), testRecord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedPath := "/audit-bucket/sidereal/2026/03/15/rbac/probe-abc-123.json"
	if receivedPath != expectedPath {
		t.Errorf("expected path %q, got %q", expectedPath, receivedPath)
	}
	if receivedSSE != "aws:kms" {
		t.Errorf("expected SSE-KMS, got %q", receivedSSE)
	}
	if receivedLockMode != "COMPLIANCE" {
		t.Errorf("expected COMPLIANCE lock mode, got %q", receivedLockMode)
	}
	if backend.Name() != "s3" {
		t.Errorf("expected name 's3', got %q", backend.Name())
	}
}

func TestS3ObjectKey(t *testing.T) {
	key := s3ObjectKey(testRecord)
	expected := "sidereal/2026/03/15/rbac/probe-abc-123.json"
	if key != expected {
		t.Errorf("expected %q, got %q", expected, key)
	}
}

// --- Retry ---

func TestRetryableBackend_Success(t *testing.T) {
	calls := 0
	mock := &mockBackend{
		exportFn: func(ctx context.Context, record AuditRecord) error {
			calls++
			return nil
		},
	}

	rb := NewRetryableBackend(mock, RetryConfig{
		InitialInterval: 1 * time.Millisecond,
		MaxRetries:      3,
		MaxElapsedTime:  1 * time.Minute,
	})

	err := rb.Export(context.Background(), testRecord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestRetryableBackend_RetryThenSuccess(t *testing.T) {
	calls := 0
	mock := &mockBackend{
		exportFn: func(ctx context.Context, record AuditRecord) error {
			calls++
			if calls < 3 {
				return fmt.Errorf("transient error")
			}
			return nil
		},
	}

	rb := NewRetryableBackend(mock, RetryConfig{
		InitialInterval: 1 * time.Millisecond,
		MaxInterval:     10 * time.Millisecond,
		MaxRetries:      5,
		MaxElapsedTime:  1 * time.Minute,
	})

	err := rb.Export(context.Background(), testRecord)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

func TestRetryableBackend_Exhausted(t *testing.T) {
	mock := &mockBackend{
		exportFn: func(ctx context.Context, record AuditRecord) error {
			return fmt.Errorf("persistent error")
		},
	}

	rb := NewRetryableBackend(mock, RetryConfig{
		InitialInterval: 1 * time.Millisecond,
		MaxInterval:     10 * time.Millisecond,
		MaxRetries:      2,
		MaxElapsedTime:  1 * time.Minute,
	})

	err := rb.Export(context.Background(), testRecord)
	if err == nil {
		t.Error("expected error after exhausting retries")
	}
	if !strings.Contains(err.Error(), "exhausted") {
		t.Errorf("expected 'exhausted' in error, got: %v", err)
	}
}

func TestRetryableBackend_ContextCancelled(t *testing.T) {
	mock := &mockBackend{
		exportFn: func(ctx context.Context, record AuditRecord) error {
			return fmt.Errorf("error")
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	rb := NewRetryableBackend(mock, RetryConfig{
		InitialInterval: 1 * time.Second,
		MaxRetries:      5,
		MaxElapsedTime:  1 * time.Minute,
	})

	err := rb.Export(ctx, testRecord)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestRetryableBackend_Name(t *testing.T) {
	mock := &mockBackend{name: "test-backend"}
	rb := NewRetryableBackend(mock, DefaultRetryConfig())
	if rb.Name() != "test-backend" {
		t.Errorf("expected name 'test-backend', got %q", rb.Name())
	}
}

func TestBackoffDelay(t *testing.T) {
	initial := 5 * time.Second
	max := 5 * time.Minute

	d0 := backoffDelay(0, initial, max)
	if d0 != 5*time.Second {
		t.Errorf("attempt 0: expected 5s, got %v", d0)
	}

	d1 := backoffDelay(1, initial, max)
	if d1 != 10*time.Second {
		t.Errorf("attempt 1: expected 10s, got %v", d1)
	}

	d10 := backoffDelay(10, initial, max)
	if d10 != max {
		t.Errorf("attempt 10: expected max %v, got %v", max, d10)
	}
}

// --- mock ---

type mockBackend struct {
	name     string
	exportFn func(ctx context.Context, record AuditRecord) error
}

func (m *mockBackend) Export(ctx context.Context, record AuditRecord) error {
	if m.exportFn != nil {
		return m.exportFn(ctx, record)
	}
	return nil
}

func (m *mockBackend) Name() string {
	if m.name != "" {
		return m.name
	}
	return "mock"
}
