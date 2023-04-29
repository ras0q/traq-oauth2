package main

import (
	"encoding/gob"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	traqoauth2 "github.com/ras0q/traq-oauth2"
	"github.com/traPtitech/go-traq"
	"golang.org/x/oauth2"
)

// Configure your client ID and redirect URL at https://bot-console.trap.jp/clients
var (
	clientID    = os.Getenv("TRAQ_CLIENT_ID")
	redirectURL = os.Getenv("TRAQ_REDIRECT_URL") // e.g. http://localhost:8080/oauth2/callback
	conf        = traqoauth2.NewConfig(clientID, redirectURL)
)

type sessionKey string

const (
	sessionName string = "traq-oauth2-example"

	codeVerifierKey sessionKey = "code_verifier"
	tokenKey        sessionKey = "access_token"
)

func main() {
	gob.Register(sessionKey(""))
	gob.Register(&oauth2.Token{})

	e := echo.New()

	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.GET("/oauth2/authorize", authorizeHandler)
	e.GET("/oauth2/callback", callbackHandler)
	e.GET("/me", getMeHandler)

	e.Logger.Fatal(e.Start(":8080"))
}

func authorizeHandler(c echo.Context) error {
	codeVerifier, err := traqoauth2.GenerateCodeVerifier()
	if err != nil {
		return internalServerError(c, err)
	}

	sess, _ := session.Get(sessionName, c)
	sess.Values[codeVerifierKey] = codeVerifier
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return internalServerError(c, err)
	}

	codeChallengeMethod, ok := traqoauth2.CodeChallengeMethodFromStr(c.QueryParam("method"))
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid code_challenge_method")
	}

	codeChallenge, err := traqoauth2.GenerateCodeChallenge(codeVerifier, codeChallengeMethod)
	if err != nil {
		return internalServerError(c, err)
	}

	authCodeURL := conf.AuthCodeURL(
		c.QueryParam("state"),
		traqoauth2.WithCodeChallenge(codeChallenge),
		traqoauth2.WithCodeChallengeMethod(codeChallengeMethod),
	)

	return c.Redirect(http.StatusFound, authCodeURL)
}

func callbackHandler(c echo.Context) error {
	sess, err := session.Get(sessionName, c)
	if err != nil {
		return internalServerError(c, err)
	}

	codeVerifier, ok := sess.Values[codeVerifierKey].(string)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	code := c.QueryParam("code")
	if code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "bad request")
	}

	ctx := c.Request().Context()
	tok, err := conf.Exchange(
		ctx,
		code,
		traqoauth2.WithCodeVerifier(codeVerifier),
	)
	if err != nil {
		return internalServerError(c, err)
	}

	sess.Values[tokenKey] = tok
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return internalServerError(c, err)
	}

	return c.String(http.StatusOK, "You are logged in!")
}

func getMeHandler(c echo.Context) error {
	sess, err := session.Get(sessionName, c)
	if err != nil {
		return internalServerError(c, err)
	}

	tok, ok := sess.Values[tokenKey].(*oauth2.Token)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
	}

	traqconf := traq.NewConfiguration()
	traqconf.HTTPClient = conf.Client(c.Request().Context(), tok)
	client := traq.NewAPIClient(traqconf)

	user, _, err := client.MeApi.GetMe(c.Request().Context()).Execute()
	if err != nil {
		return internalServerError(c, err)
	}

	return c.JSON(http.StatusOK, user)
}

func internalServerError(c echo.Context, err error) error {
	c.Logger().Error(err)
	return echo.NewHTTPError(http.StatusInternalServerError, "Internal Server Error")
}
