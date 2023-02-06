# traq-oauth2

[![Go Reference](https://pkg.go.dev/badge/github.com/ras0q/traq-oauth2.svg)](https://pkg.go.dev/github.com/ras0q/traq-oauth2)

traq-oauth2 provides support for OAuth2 authentication in [traQ](https://github.com/traPtitech/traQ)

## Features

- [Authorization Code Flow](https://www.rfc-editor.org/rfc/rfc6749#section-1.3.1)
  - Only this flow is supported in traQ.
- [Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636)
  - PKCE is supported in traQ.
- Few dependencies
  - traq-oauth2 only depends on [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2) and standard libraries.

## Installation

```bash
go get github.com/traPtitech/traq-oauth2
```

## Usage

See [example](./example)
