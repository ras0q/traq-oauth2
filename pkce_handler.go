package traqoauth2

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2"
)

var (
	ErrGenerateCodeverifier  = errors.New("failed to generate code verifier")
	ErrGenerateCodechallenge = errors.New("failed to generate code challenge")
	ErrExchangeCode          = errors.New("failed to exchange code")
)

// AuthorizeWithPKCE returns the code verifier and the authorization URL.
func (c *Config) AuthorizeWithPKCE(codeChallengeMethod CodeChallengeMethod, state string) (codeVerifier string, authURL string, err error) {
	codeVerifier, err = GenerateCodeVerifier()
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrGenerateCodeverifier, err)
	}

	codeChallenge, err := GenerateCodeChallenge(codeVerifier, codeChallengeMethod)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrGenerateCodechallenge, err)
	}

	authURL = c.AuthCodeURL(
		state,
		WithCodeChallenge(codeChallenge),
		WithCodeChallengeMethod(codeChallengeMethod),
	)

	return codeVerifier, authURL, nil
}

// CallbackWithPKCE exchanges the code for a token.
func (c *Config) CallbackWithPKCE(ctx context.Context, codeVerifier string, code string) (*oauth2.Token, error) {
	tok, err := c.Exchange(
		ctx,
		code,
		WithCodeVerifier(codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExchangeCode, err)
	}

	return tok, nil
}
