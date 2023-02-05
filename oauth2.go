package traqoauth2

import (
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
