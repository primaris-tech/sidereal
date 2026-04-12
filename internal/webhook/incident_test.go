package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_Deliver(t *testing.T) {
	var receivedBody []byte
	var receivedAuth string
	var receivedContentType string
	var receivedUserAgent string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedContentType = r.Header.Get("Content-Type")
		receivedUserAgent = r.Header.Get("User-Agent")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(Config{
		URL:        server.URL,
		AuthToken:  "Bearer test-token",
		HTTPClient: server.Client(),
	})

	payload := IncidentPayload{
		IncidentName:         "sidereal-incident-aaaaaaaa",
		ProbeType:            "rbac",
		TargetNamespace:      "production",
		Outcome:              "Fail",
		ControlEffectiveness: "Ineffective",
		Severity:             "High",
		Description:          "Cross-namespace access allowed",
		ControlID:            "AC-3",
		ProbeResultRef:       "sidereal-result-aaaaaaaa",
		Timestamp:            time.Date(2026, 3, 15, 10, 30, 0, 0, time.UTC),
	}

	err := client.Deliver(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedAuth != "Bearer test-token" {
		t.Errorf("expected auth header, got %q", receivedAuth)
	}
	if receivedContentType != "application/json" {
		t.Errorf("expected JSON content type, got %q", receivedContentType)
	}
	if receivedUserAgent != "sidereal-incident-webhook/1.0" {
		t.Errorf("unexpected user agent: %q", receivedUserAgent)
	}

	var parsed IncidentPayload
	if err := json.Unmarshal(receivedBody, &parsed); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}
	if parsed.ProbeType != "rbac" {
		t.Errorf("expected probeType rbac, got %q", parsed.ProbeType)
	}
	if parsed.Severity != "High" {
		t.Errorf("expected severity High, got %q", parsed.Severity)
	}
}

func TestClient_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewClient(Config{
		URL:        server.URL,
		HTTPClient: server.Client(),
	})

	err := client.Deliver(context.Background(), IncidentPayload{})
	if err == nil {
		t.Error("expected error for 503 response")
	}
}

func TestClient_NoURL(t *testing.T) {
	client := NewClient(Config{})

	err := client.Deliver(context.Background(), IncidentPayload{})
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestClient_CustomAuthHeader(t *testing.T) {
	var receivedHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-ServiceNow-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(Config{
		URL:        server.URL,
		AuthToken:  "snow-token-123",
		AuthHeader: "X-ServiceNow-Token",
		HTTPClient: server.Client(),
	})

	err := client.Deliver(context.Background(), IncidentPayload{IncidentName: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedHeader != "snow-token-123" {
		t.Errorf("expected custom auth header, got %q", receivedHeader)
	}
}

func TestClient_NoAuth(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(Config{
		URL:        server.URL,
		HTTPClient: server.Client(),
	})

	err := client.Deliver(context.Background(), IncidentPayload{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedAuth != "" {
		t.Errorf("expected no auth header, got %q", receivedAuth)
	}
}
