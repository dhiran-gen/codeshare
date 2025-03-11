package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httputil"
	"net/url"

log "github.com/sirupsen/logrus"
	"github.com/golang-jwt/jwt"
)

func parseDpop(formData url.Values, dPopParser *jwt.Parser, r *httputil.ProxyRequest) (url.Values, error) {
	dpopJwtStr := formData.Get("dpop")
	dPopJwt, _, err := dPopParser.ParseUnverified(dpopJwtStr, jwt.MapClaims{})

	if err != nil {
		log.WithContext(r.In.Context()).Errorf("error parsing dpop token: %v", err)
		return formData, err
	}

	claims := dPopJwt.Claims.(jwt.MapClaims)

	// Check if jwk claim exists
	cnfInterface, exists := claims["jwk"]
	if !exists {
		err := fmt.Errorf("missing jwk claim in dpop token")
		log.WithContext(r.In.Context()).Error(err)
		return formData, err
	}

	// Check if jwk is a map
	cnf, ok := cnfInterface.(map[string]interface{})
	if !ok {
		err := fmt.Errorf("invalid jwk type in dpop token")
		log.WithContext(r.In.Context()).Error(err)
		return formData, err
	}

	cnfJwkbytes, err := json.Marshal(cnf)
	if err != nil {
		log.WithContext(r.In.Context()).Errorf("error marshalling jwk: %v", err)
		return formData, err
	}

	cnfEncodedStr := base64.StdEncoding.EncodeToString(cnfJwkbytes)
	formData.Set("cnf_key", cnfEncodedStr)
	// SetRequestFormData(formData, r.Out)

	return formData, nil
}
