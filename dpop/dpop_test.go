package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

func TestParseDpop(t *testing.T) {
	tests := []struct {
		name      string
		formData  url.Values
		setupJWT  func() string
		expectErr bool
	}{
		{
			name: "Valid DPoP Token",
			formData: url.Values{
				"dpop": []string{""}, // Will be replaced by setupJWT function
			},
			setupJWT: func() string {
				claims := jwt.MapClaims{
					"jwk": map[string]interface{}{
						"kty": "RSA",
						"n":   "some-key",
					},
				}
				token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
				dpopStr, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
				return dpopStr
			},
			expectErr: false,
		},
		{
			name: "Invalid DPoP Token",
			formData: url.Values{
				"dpop": []string{"invalid_token"},
			},
			setupJWT:  func() string { return "invalid_token" },
			expectErr: true,
		},
		{
			name: "Missing JWK Claim",
			formData: url.Values{
				"dpop": []string{""}, // Will be replaced by setupJWT function
			},
			setupJWT: func() string {
				claims := jwt.MapClaims{}
				token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
				dpopStr, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
				return dpopStr
			},
			expectErr: true,
		},
		{
			name: "Invalid JWK Type",
			formData: url.Values{
				"dpop": []string{""}, // Will be replaced by setupJWT function
			},
			setupJWT: func() string {
				claims := jwt.MapClaims{
					"jwk": "invalid_type",
				}
				token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
				dpopStr, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
				return dpopStr
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup formData
			if tt.setupJWT != nil {
				tt.formData.Set("dpop", tt.setupJWT())
			}

			// Create a real ProxyRequest with proper context
			mockReq := &httputil.ProxyRequest{
				In:  &http.Request{},
				Out: &http.Request{},
			}

			// Call function
			result, err := parseDpop(tt.formData, &jwt.Parser{}, mockReq)

			// Assertions
			if tt.expectErr {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.Contains(t, result, "cnf_key", "Expected cnf_key to be present in formData")
				
				// Fix the base64 decoding and JSON unmarshalling
				decoded, decodeErr := base64.StdEncoding.DecodeString(result.Get("cnf_key"))
				assert.NoError(t, decodeErr, "Expected no error decoding base64")
				
				var jwk map[string]interface{}
				unmarshalErr := json.Unmarshal(decoded, &jwk)
				assert.NoError(t, unmarshalErr, "Expected no error unmarshalling JSON")
				assert.Contains(t, jwk, "kty", "Expected 'kty' key in JWK")
			}
		})
	}
}