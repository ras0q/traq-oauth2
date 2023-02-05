package webapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	traqoauth2 "github.com/ras0q/traq-oauth2"
)

type jsonMap map[string]interface{}

// Configure your client ID and redirect URL at https://bot-console.trap.jp/clients
var (
	clientID    = os.Getenv("TRAQ_CLIENT_ID")
	redirectURL = os.Getenv("TRAQ_REDIRECT_URL") // e.g. http://localhost:8080/oauth2/callback
	conf        = traqoauth2.NewConfig(clientID, redirectURL)
)

func StartOauth2Server() {
	server := http.NewServeMux()

	server.HandleFunc("/oauth2/authorize", authorizeHandler)
	server.HandleFunc("/oauth2/callback", callbackHandler)
	server.HandleFunc("/me", getMeHandler)

	log.Fatal(http.ListenAndServe(":8080", server))
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	const alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var codeChallenge string
	for i := 0; i < rand.Intn(128-43)+43; i++ {
		codeChallenge += string(alphanumeric[rand.Intn(len(alphanumeric))])
	}

	if r.URL.Query().Get("method") == "S256" {
		codeChallenge = base64.RawURLEncoding.EncodeToString([]byte(codeChallenge))
	}

	setToSession("code_challenge", codeChallenge, 1*time.Hour)

	authCodeURL := conf.AuthCodeURL(
		r.URL.Query().Get("state"),
		traqoauth2.WithCodeChallenge(codeChallenge),
	)
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	codeVerifier, ok := getFromSession("code_challenge").(string)
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
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}

	client := conf.Client(ctx, tok)
	res, err := client.Get("https://q.trap.jp/api/v3/users/me")
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
	defer res.Body.Close()

	b, err := io.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}

	var user jsonMap
	if err := json.Unmarshal(b, &user); err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}

	setToSession("user", user, 1*time.Hour)

	if _, err := w.Write([]byte("You are logged in!")); err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func getMeHandler(w http.ResponseWriter, _ *http.Request) {
	user, ok := getFromSession("user").(jsonMap)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := json.Marshal(user)
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(body); err != nil {
		log.Println(err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}