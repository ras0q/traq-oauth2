package traqoauth2

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateCodeVerifier generates a code verifier.
// Ref: https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
func GenerateCodeVerifier() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
