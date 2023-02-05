package traqoauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/oauth2"
)

// GenerateCodeVerifier generates a code verifier.
// Ref: https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
func GenerateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CodeChallengeMethod represents the code challenge method.
type CodeChallengeMethod string

const (
	// CodeChallengePlain is the PKCE "plain" method.
	CodeChallengePlain CodeChallengeMethod = "plain"
	// CodeChallengeS256 is the PKCE "S256" method.
	CodeChallengeS256 CodeChallengeMethod = "S256"
)

// String returns the string representation of the code challenge method.
func (m CodeChallengeMethod) String() string {
	if m == CodeChallengePlain || m == CodeChallengeS256 {
		return string(m)
	}

	fmt.Printf("WARN: unavailable code challenge method: %s\n", string(m))

	return ""
}

// GenerateCodeChallenge generates the code challenge from the code verifier.
// Ref: https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
func (m CodeChallengeMethod) GenerateCodeChallenge(codeVerifier string) (string, error) {
	switch m {
	case CodeChallengePlain:
		return codeVerifier, nil
	case CodeChallengeS256:
		h := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(h[:]), nil
	default:
		return "", fmt.Errorf("unavailable code challenge method: %s", string(m))
	}
}

// WithCodeChallenge sets the code_challenge parameter.
func WithCodeChallenge(codeChallenge string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_challenge", codeChallenge)
}

// WithCodeChallengeMethod sets the code_challenge_method parameter.
// The default value is "plain".
// If you want to use "S256", use WithCodeChallengeMethod(traqoauth2.CodeChallenge).
func WithCodeChallengeMethod(codeChallengeMethod CodeChallengeMethod) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod.String())
}

// WithCodeVerifier sets the code_verifier parameter.
// If you had use WithCodeChallenge, you also must use this.
func WithCodeVerifier(codeVerifier string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_verifier", codeVerifier)
}
