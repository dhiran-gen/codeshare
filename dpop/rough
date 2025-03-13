package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt"
)

func TestParseDpop(t *testing.T) {
	dPopParser := &jwt.Parser{}

	createProxyRequest := func() *httputil.ProxyRequest {
		req, _ := http.NewRequest("POST", "https://example.com", nil)
		outReq, _ := http.NewRequest("POST", "https://example.com", nil)
		return &httputil.ProxyRequest{
			In:  req,
			Out: outReq,
		}
	}

	tests := []struct {
		name     string
		dpopJWT  string
		wantErr  bool
	}{
		{
			name: "valid dpop token",
			dpopJWT: createValidDpopToken(),
			wantErr: false,
		},
		{
			name: "invalid token format",
			dpopJWT: "not.a.validtoken",
			wantErr: true,
		},
		{
			name: "completely invalid token",
			dpopJWT: "invalid-token",
			wantErr: true,
		},
		{
			name: "empty token",
			dpopJWT: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formData := url.Values{}
			formData.Set("dpop", tt.dpopJWT)
			
			r := createProxyRequest()
			
			result, err := parseDpop(formData, dPopParser, r)
		
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDpop() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr {
				if result.Get("cnf_key") == "" {
					t.Errorf("cnf_key was not set")
				}
				
				decodedBytes, err := base64.StdEncoding.DecodeString(result.Get("cnf_key"))
				if err != nil {
					t.Errorf("Failed to decode cnf_key: %v", err)
				}
				
				var claimsMap map[string]interface{}
				if err := json.Unmarshal(decodedBytes, &claimsMap); err != nil {
					t.Errorf("cnf_key is not valid JSON: %v", err)
				}
			}
		})
	}
}

// Helper function to create a valid DPoP token for testing
func createValidDpopToken() string {
	claims := jwt.MapClaims{
		"jti": "123456",
		"htm": "POST",
		"htu": "https://example.com/token",
		"iat": 1516239022,
		"cnf": map[string]interface{}{
			"jwk": map[string]interface{}{
				"kty": "RSA",
				"e": "AQAB",
				"kid": "test-key-id",
				"n": "someBase64Value",
			},
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Using a simple secret for test purposes
	tokenString, _ := token.SignedString([]byte("test-secret"))
	return tokenString
}
