package web

import "net/http"

func (s *Service) getOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	jsonStr := `{
		"issuer": "https://accounts.google.com",
		"authorization_endpoint": "http://localhost:8080/web/authorize",
		"token_endpoint": "http://localhost:8080/v1/oauth/tokens",
		"userinfo_endpoint": "http://localhost:8080/v1/oauth/introspect",
		"revocation_endpoint": "https://accounts.google.com/o/oauth2/revoke",
		"jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
		"response_types_supported": [
		"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
			"none"
		],
		"subject_types_supported": [
		"public"
		],
		"id_token_signing_alg_values_supported": [
		"RS256"
		],
		"scopes_supported": [
		"openid",
			"email",
			"profile"
		],
		"token_endpoint_auth_methods_supported": [
		"client_secret_post",
			"client_secret_basic"
		],
		"claims_supported": [
		"aud",
			"email",
			"email_verified",
			"exp",
			"family_name",
			"given_name",
			"iat",
			"iss",
			"locale",
			"name",
			"picture",
			"sub"
		],
		"code_challenge_methods_supported": [
		"plain",
			"S256"
		]
	}`


	jsonBytes := []byte(jsonStr)
	w.Header().Set("X-Frame-Options", "deny")
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)
}