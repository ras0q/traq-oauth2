package traqoauth2

import (
	"golang.org/x/oauth2"
)

var TraQ = oauth2.Endpoint{
	AuthURL:  "https://q.trap.jp/api/v3/oauth2/authorize",
	TokenURL: "https://q.trap.jp/api/v3/oauth2/token",
}

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

func WithCodeChallenge(codeChallenge string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_challenge", codeChallenge)
}

func WithCodeChallengeMethod(codeChallengeMethod string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod)
}

func WithCodeVerifier(codeVerifier string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("code_verifier", codeVerifier)
}
