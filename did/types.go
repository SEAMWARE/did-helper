package did

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kid     string   `json:"kid"`
	Kty     string   `json:"kty"`
	Alg     string   `json:"alg"`
	Use     string   `json:"use"`
	N       string   `json:"n,omitempty"`
	E       string   `json:"e,omitempty"`
	X5c     []string `json:"x5c"`
	X5t     string   `json:"x5t"`
	X5tS256 string   `json:"x5t#S256"`
	Crv     string   `json:"crv,omitempty"`
	X       string   `json:"x,omitempty"`
	Y       string   `json:"y,omitempty"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
