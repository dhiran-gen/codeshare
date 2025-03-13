package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httputil"
	"net/url"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

func parseDpop(formData url.Values, dPopParser *jwt.Parser, r *httputil.ProxyRequest) (url.Values, error) {
	dpopJwtStr := formData.Get("dpop")
	dPopJwt, _, err := dPopParser.ParseUnverified(dpopJwtStr, jwt.MapClaims{})

	if err != nil {
		log.WithContext(r.In.Context()).Errorf("error parsing dpop token: %v", err)
		return formData, err
	}

	claims := dPopJwt.Claims.(jwt.MapClaims)

	cnfJwkbytes, err := json.Marshal(claims)
	if err != nil {
		log.WithContext(r.In.Context()).Errorf("error marshalling jwk: %v", err)
		return formData, err
	}

	cnfEncodedStr := base64.StdEncoding.EncodeToString(cnfJwkbytes)
	formData.Set("cnf_key", cnfEncodedStr)
	// SetRequestFormData(formData, r.Out)

	return formData, nil
}
