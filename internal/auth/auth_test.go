package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := GetAPIKey(req.Header)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKeyy_MalformedAuthHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "InvalidFormat")

	_, err := GetAPIKey(req.Header)

	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected malformed authorization header, got %v", err)
	}
}

func TestGetAPIKey_ValidAuthHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "ApiKey valid-api-key")

	apikey, err := GetAPIKey(req.Header)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if apikey != "valid-api-key" {
		t.Errorf("expected valid-api-key, got %v", apikey)
	}
}
