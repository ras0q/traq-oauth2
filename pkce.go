package traqoauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/oauth2"
)

// GenerateCodeVerifier generates a code verifier.
// Ref: https://www.rfc-editor.org/rfc/rfc7636#section-4.1
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

// GenerateCodeChallenge generates the code challenge from the code verifier.
// Ref: https://www.rfc-editor.org/rfc/rfc7636#section-4.2
func GenerateCodeChallenge(codeVerifier string, codeChallengeMethod CodeChallengeMethod) (string, error) {
	switch codeChallengeMethod {
	case CodeChallengePlain:
		return codeVerifier, nil
	case CodeChallengeS256:
		h := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(h[:]), nil
	default:
		return "", fmt.Errorf("unavailable code challenge method: %s", codeChallengeMethod)
	}
}

// WithCodeChallenge sets the code_challenge parameter.
func WithCodeChallenge(codeChallenge string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_challenge", codeChallenge)
}

// WithCodeChallengeMethod sets the code_challenge_method parameter.
// The default value is "plain".
// If you want to use "S256", use WithCodeChallengeMethod(traqoauth2.CodeChallengeS256).
func WithCodeChallengeMethod(codeChallengeMethod CodeChallengeMethod) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_challenge_method", string(codeChallengeMethod))
}

// WithCodeVerifier sets the code_verifier parameter.
// If you had use WithCodeChallenge, you also must use this.
func WithCodeVerifier(codeVerifier string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_verifier", codeVerifier)
}
