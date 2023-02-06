package traqoauth2

import (
	"golang.org/x/oauth2"
)

// Traq is the OAuth2 endpoint for traQ.
var TraQ = oauth2.Endpoint{
	AuthURL:  "https://q.trap.jp/api/v3/oauth2/authorize",
	TokenURL: "https://q.trap.jp/api/v3/oauth2/token",
}

// Config is a wrapper of oauth2.Config.
type Config struct {
	*oauth2.Config
}

// NewConfig returns a new oauth2.Config for traQ.
func NewConfig(clientID string, redirectURL string, opts ...func(*Config)) *Config {
	c := &Config{
		Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: "",
			Endpoint:     TraQ,
			RedirectURL:  redirectURL,
			Scopes:       []string{},
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}
