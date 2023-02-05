package traqoauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/oauth2"
)

// Traq is the OAuth2 endpoint for traQ.
var TraQ = oauth2.Endpoint{
	AuthURL:  "https://q.trap.jp/api/v3/oauth2/authorize",
	TokenURL: "https://q.trap.jp/api/v3/oauth2/token",
}

// NewConfig returns a new oauth2.Config for traQ.
func NewConfig(clientID string, redirectURL string, opts ...func(*oauth2.Config)) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: "",
		Endpoint:     TraQ,
		RedirectURL:  redirectURL,
		Scopes:       []string{},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
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
func (m CodeChallengeMethod) GenerateCodeChallenge(codeVerifier string) string {
	switch m {
	case CodeChallengePlain:
		return codeVerifier
	case CodeChallengeS256:
		h := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(h[:])
	default:
		fmt.Printf("WARN: unavailable code challenge method: %s\n", string(m))

		return ""
	}
}
