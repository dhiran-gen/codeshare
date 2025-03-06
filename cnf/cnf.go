package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/gin-gonic/gin"
)

// DPoPPayload represents the JWT payload structure
type DPoPPayload struct {
	Iat int64  `json:"iat"`  // Issued At
	Htm string `json:"htm"`  // HTTP Method
	Htu string `json:"htu"`  // HTTP URL
	Jti string `json:"jti"`  // Unique Token ID
	Cnf struct {
		Jwk struct {
			Kty string `json:"kty"` // Key Type (EC)
			Crv string `json:"crv"` // Curve Type (P-256, P-384, etc.)
			X   string `json:"x"`   // X coordinate (Base64)
			Y   string `json:"y"`   // Y coordinate (Base64)
		} `json:"jwk"`
	} `json:"cnf"`
}

// ExtractDPoPHeader extracts and decodes the DPoP token from the request
func ExtractDPoPHeader(c *gin.Context) {
	// Get DPoP token from the Authorization header
	dpopToken := c.GetHeader("DPoP")
	if dpopToken == "" {
		c.JSON(400, gin.H{"error": "DPoP token is missing"})
		return
	}

	// Split JWT into three parts: Header.Payload.Signature
	parts := strings.Split(dpopToken, ".")
	if len(parts) != 3 {
		c.JSON(400, gin.H{"error": "Invalid DPoP token format"})
		return
	}

	// Decode the payload (2nd part of JWT)
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to decode DPoP payload"})
		return
	}

	// Parse the payload JSON into the struct
	var payload DPoPPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		c.JSON(400, gin.H{"error": "Failed to parse DPoP payload"})
		return
	}

	// Extract cnf.jwk (confirmation key)
	cnfKey, err := ConvertJWKToECDSA(payload.Cnf.Jwk)
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to convert cnf.jwk to public key"})
		return
	}

	// Successfully extracted and reconstructed public key
	c.JSON(200, gin.H{
		"message": "DPoP token processed successfully",
		"public_key": gin.H{
			"X":   payload.Cnf.Jwk.X,
			"Y":   payload.Cnf.Jwk.Y,
			"Crv": payload.Cnf.Jwk.Crv,
		},
		"ecdsa_public_key": fmt.Sprintf("%+v", cnfKey),
	})
}

// ConvertJWKToECDSA converts JWK to ECDSA Public Key
func ConvertJWKToECDSA(jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}) (*ecdsa.PublicKey, error) {
	// Decode Base64Url encoded X and Y coordinates
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X coordinate")
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Y coordinate")
	}

	// Select curve based on `crv` field
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	// Construct ECDSA Public Key
	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	return publicKey, nil
}

func main() {
	r := gin.Default()

	// API Endpoint to extract DPoP header
	r.GET("/extract-dpop", ExtractDPoPHeader)

	r.Run(":8080") // Run on localhost:8080
}