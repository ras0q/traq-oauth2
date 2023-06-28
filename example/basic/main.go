package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	traqoauth2 "github.com/ras0q/traq-oauth2"
)

// Configure your client ID and redirect URL at https://bot-console.trap.jp/clients
var (
	clientID    = os.Getenv("TRAQ_CLIENT_ID")
	redirectURL = os.Getenv("TRAQ_REDIRECT_URL")

	printToken = flag.Bool("print-token", false, "print access token (default: false)")
)

func main() {
	flag.Parse()

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

	if *printToken {
		fmt.Printf("Your token: %s\n", tok.AccessToken)
	}

	client := conf.Client(ctx, tok)
	res, err := client.Get("https://q.trap.jp/api/v3/users/me")
	if err != nil {
		panic(err)
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Your info: %s\n", b)
}
