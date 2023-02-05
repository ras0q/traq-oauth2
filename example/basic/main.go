package main

import (
	"context"
	"fmt"
	"os"

	traqoauth2 "github.com/ras0q/traq-oauth2"
)

// Configure your client ID and redirect URL at https://bot-console.trap.jp/clients
var (
	clientID    = os.Getenv("CLIENT_ID")
	redirectURL = os.Getenv("REDIRECT_URL")
)

func main() {
	conf := traqoauth2.NewConfig(clientID, redirectURL)
	authURL := conf.AuthCodeURL("STATE")
	fmt.Printf("Visit the URL for the auth dialog:\n%s\n", authURL)

	var code string
	fmt.Print("Enter the code:")
	fmt.Scan(&code)

	ctx := context.Background()
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		panic(err)
	}

	client := conf.Client(ctx, tok)
	res, err := client.Get("https://q.trap.jp/api/v3/users/me")
	if err != nil {
		panic(err)
	}

	body := make([]byte, 10000)
	_, _ = res.Body.Read(body)
	fmt.Printf("ユーザー情報: %s\n", body)
}
