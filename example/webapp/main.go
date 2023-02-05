package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

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

	codeChallenge := codeVerifier
	codeChallengeMethod := traqoauth2.CodeChallengePlain
	if m := traqoauth2.CodeChallengeMethod(r.URL.Query().Get("method")); m != "" && m != codeChallengeMethod {
		codeChallenge, err = m.GenerateCodeChallenge(codeVerifier)
		if err != nil {
			handleInternalServerError(w, err)
			return
		}

		codeChallengeMethod = m
	}

	setToSession("code_verifier", codeVerifier, 1*time.Hour)
	setToSession("code_challenge", codeChallenge, 1*time.Hour)
	setToSession("code_challenge_method", codeChallengeMethod, 1*time.Hour)

	authCodeURL := conf.AuthCodeURL(
		r.URL.Query().Get("state"),
		traqoauth2.WithCodeChallenge(codeChallenge),
		traqoauth2.WithCodeChallengeMethod(codeChallengeMethod),
	)
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	codeVerifier, ok := getFromSession("code_verifier").(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
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

	setToSession("user", user, 1*time.Hour)

	if _, err := w.Write([]byte("You are logged in!")); err != nil {
		handleInternalServerError(w, err)
		return
	}
}

func getMeHandler(w http.ResponseWriter, _ *http.Request) {
	user, ok := getFromSession("user").(userInfo)
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

var mySession = map[string]interface{}{}

func getFromSession(key string) interface{} {
	return mySession[key]
}

func setToSession(key string, value interface{}, duration time.Duration) {
	mySession[key] = value

	go func() {
		time.Sleep(duration)
		delete(mySession, key)
	}()
}
