package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	traqoauth2 "github.com/ras0q/traq-oauth2"
)

type userInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// Configure your client ID and redirect URL at https://bot-console.trap.jp/clients
var (
	clientID    = os.Getenv("TRAQ_CLIENT_ID")
	redirectURL = os.Getenv("TRAQ_REDIRECT_URL") // e.g. http://localhost:8080/oauth2/callback
	conf        = traqoauth2.NewConfig(clientID, redirectURL)
)

func main() {
	server := http.NewServeMux()

	server.HandleFunc("/oauth2/authorize", authorizeHandler)
	server.HandleFunc("/oauth2/callback", callbackHandler)
	server.HandleFunc("/me", getMeHandler)

	log.Println("Listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", server))
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	codeVerifier, err := traqoauth2.GenerateCodeVerifier()
	if err != nil {
		handleInternalServerError(w, err)
		return
	}

	session, err := globalManager.RetrieveSession(w, r)
	if err != nil {
		handleInternalServerError(w, err)
		return
	}

	session.Set(codeVerifierKey, codeVerifier)

	codeChallengeMethod := traqoauth2.CodeChallengeMethod(r.URL.Query().Get("method"))
	if codeChallengeMethod == "" {
		codeChallengeMethod = traqoauth2.CodeChallengePlain
	}

	codeChallenge, err := traqoauth2.GenerateCodeChallenge(codeVerifier, codeChallengeMethod)
	if err != nil {
		handleInternalServerError(w, err)
		return
	}

	authCodeURL := conf.AuthCodeURL(
		r.URL.Query().Get("state"),
		traqoauth2.WithCodeChallenge(codeChallenge),
		traqoauth2.WithCodeChallengeMethod(codeChallengeMethod),
	)
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	session, err := globalManager.RetrieveSession(w, r)
	if err != nil {
		handleInternalServerError(w, err)
		return
	}

	codeVerifier, ok := session.Get(codeVerifierKey).(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	tok, err := conf.Exchange(
		ctx,
		code,
		traqoauth2.WithCodeVerifier(codeVerifier),
	)
	if err != nil {
		handleInternalServerError(w, err)
		return
	}

	client := conf.Client(ctx, tok)
	res, err := client.Get("https://q.trap.jp/api/v3/users/me")
	if err != nil {
		handleInternalServerError(w, err)
		return
	}
	defer res.Body.Close()

	b, err := io.ReadAll(res.Body)
	if err != nil {
		handleInternalServerError(w, err)
		return
	}

	var user userInfo
	if err := json.Unmarshal(b, &user); err != nil {
		handleInternalServerError(w, err)
		return
	}

	session.Set(userKey, user)

	if _, err := w.Write([]byte("You are logged in!")); err != nil {
		handleInternalServerError(w, err)
		return
	}
}

func getMeHandler(w http.ResponseWriter, r *http.Request) {
	session, err := globalManager.RetrieveSession(w, r)
	if err != nil {
		handleInternalServerError(w, err)
		return
	}

	user, ok := session.Get(userKey).(userInfo)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(user)
	if err != nil {
		handleInternalServerError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(body); err != nil {
		handleInternalServerError(w, err)
		return
	}
}

func handleInternalServerError(w http.ResponseWriter, err error) {
	log.Println(err)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

type (
	sessionKey string
	session    map[sessionKey]interface{}
	manager    map[string]session
)

const (
	sessionName string = "traq-oauth2-example"

	codeVerifierKey        sessionKey = "code_verifier"
	userKey                sessionKey = "user"
)

var (
	globalManager = make(manager)
	mux           = sync.Mutex{}
)

func (m manager) RetrieveSession(w http.ResponseWriter, r *http.Request) (session, error) {
	mux.Lock()
	defer mux.Unlock()

	cookie, err := r.Cookie(sessionName)
	if errors.Is(err, http.ErrNoCookie) {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}

		id := base64.URLEncoding.EncodeToString(b)
		s := make(session)
		m[id] = s

		http.SetCookie(w, &http.Cookie{
			Name:  sessionName,
			Value: id,
		})

		return session{}, nil
	} else if err != nil {
		return nil, err
	}

	s, ok := m[cookie.Value]
	if !ok {
		return session{}, nil
	}

	return s, nil
}

func (s session) Get(key sessionKey) interface{} {
	mux.Lock()
	defer mux.Unlock()

	return s[key]
}

func (s session) Set(key sessionKey, value interface{}) {
	mux.Lock()
	defer mux.Unlock()

	s[key] = value
}
