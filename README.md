# GOAuth

[![Go Reference](https://pkg.go.dev/badge/github.com/Suhaibinator/GOAuth.svg)](https://pkg.go.dev/github.com/Suhaibinator/GOAuth)
[![Go](https://github.com/Suhaibinator/GOAuth/actions/workflows/go.yml/badge.svg)](https://github.com/Suhaibinator/GOAuth/actions/workflows/go.yml)

Go package providing handlers for common OAuth 2.0 Providers, simplifying the process of adding social logins to your Go applications.

## Overview

This package aims to provide a consistent interface for handling OAuth 2.0 authentication flows for various providers. It leverages the standard `golang.org/x/oauth2` library for most providers, ensuring robust and well-maintained core logic.

**Current Status:**
*   Providers (Google, GitHub, Discord, LinkedIn, Facebook) have been refactored to use `golang.org/x/oauth2`.
*   Sign in with Apple now includes dynamic client secret generation. You should still verify the returned ID token in your application.
*   Basic GoDoc comments have been added.
*   An example server demonstrates usage (`examples/simple_server/main.go`).
*   Tokens can be refreshed via `OAuthHandler.RefreshToken`.
*   **Testing is currently missing.**

## Supported Providers (Partial List)

*   Google
*   GitHub
*   Discord
*   Quran.Foundation
*   LinkedIn
*   Facebook
*   Apple
*   Okta

## Installation

```bash
go get github.com/Suhaibinator/GOAuth
```

## Quick Start

This project requires **Go 1.24** or newer. The example server demonstrates how to integrate GOAuth with a web application.

```bash
# build all packages
go build -v ./...

# run the example server
go run examples/simple_server/main.go
```

The example reads provider credentials from environment variables. Before running, export values similar to the following:

```bash
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export GITHUB_CLIENT_ID="your-github-client-id"
export GITHUB_CLIENT_SECRET="your-github-client-secret"
export OKTA_CLIENT_ID="your-okta-client-id"
export OKTA_CLIENT_SECRET="your-okta-client-secret"
export OKTA_DOMAIN="your-okta-domain.okta.com"
# ...other provider variables...
```

Then visit `http://localhost:8080` to try the login flows.

## Basic Usage

See the example server in `examples/simple_server/main.go` for a complete demonstration of how to initialize the handler and set up login/callback routes.

```go
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/Suhaibinator/GOAuth/pkg/auth"
	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewDevelopment() // Initialize logger
	defer logger.Sync()

	// Configure providers with your credentials
	oauthConfig := &auth.OAuthConfig{
		GoogleOAuthClientID:     "YOUR_GOOGLE_CLIENT_ID",
		GoogleOAuthClientSecret: "YOUR_GOOGLE_CLIENT_SECRET",
		GoogleOAuthRedirectURL:  "http://localhost:8080/callback/google",

		GitHubOAuthClientID:     "YOUR_GITHUB_CLIENT_ID",
		GitHubOAuthClientSecret: "YOUR_GITHUB_CLIENT_SECRET",
               GitHubOAuthRedirectURL:  "http://localhost:8080/callback/github",

                // Apple credentials
                AppleOAuthClientID:   "YOUR_APPLE_SERVICE_ID",
                AppleOAuthTeamID:     "YOUR_TEAM_ID",
                AppleOAuthKeyID:      "YOUR_KEY_ID",
                AppleOAuthPrivateKey: "-----BEGIN PRIVATE KEY-----...",
                AppleOAuthRedirectURL: "http://localhost:8080/callback/apple",

                // Okta credentials
                OktaOAuthClientID:     "YOUR_OKTA_CLIENT_ID",
                OktaOAuthClientSecret: "YOUR_OKTA_CLIENT_SECRET",
                OktaOAuthRedirectURL:  "http://localhost:8080/callback/okta",
                OktaOAuthDomain:       "your-domain.okta.com",

                // ... configure other providers ...

		TraceIdKey: "X-Request-ID", // Optional: For context logging
	}

	// Create the main handler
	oauthHandler := auth.NewOAuthHandler(logger.Named("GOAuth"), oauthConfig)
	if oauthHandler == nil {
		log.Fatal("Failed to create OAuth handler")
	}

	// Register providers based on config
	oauthHandler.RegisterOAuthProviders(context.Background())

	// Setup HTTP routes (see example server for details)
	// http.HandleFunc("/login/google", ...)
	// http.HandleFunc("/callback/google", ...)
	// ...

	log.Println("Starting server...")
	// http.ListenAndServe(":8080", nil) // Add your router/mux
}

```

## User Data Structure

GOAuth normalizes user data from all providers into a common `User` struct:

```go
type User struct {
    Username  string  // Display name or full name (see note below)
    Email     string  // User's email address
    AvatarUrl string  // Profile picture URL
    FirstName string  // First/given name
    LastName  string  // Last/family name
}
```

### Username Field Behavior

The `Username` field contains human-readable names, but the exact content varies by provider:

| Provider | Username Contains | Example |
|----------|------------------|---------|
| Google | Full name | "John Doe" |
| GitHub | Display name (falls back to GitHub username) | "John Doe" or "johndoe" |
| Discord | Global display name (falls back to username) | "John" or "john#1234" |
| LinkedIn | Full name (First + Last) | "John Doe" |
| Facebook | Full name | "John Doe" |
| Apple | Full name (only available on first sign-in) | "John Doe" or "Apple User" |
| Quran.Foundation | Full name | "John Doe" |
| Okta | Full name (falls back to preferred username) | "John Doe" or "john.doe" |

**Note:** The `Username` field does NOT contain unique provider IDs. If you need to store a unique identifier for the user, you should generate one based on the provider and email combination, or maintain a separate mapping in your application.

## Improvements & Future Work

*   **Apple Sign In:** Add full ID token validation using Apple's public keys.
*   **Testing:** Add comprehensive unit and integration tests for all providers.
*   **Error Handling:** Refine error types and context.
*   **State Management:** Implement robust CSRF protection using state parameters (the example includes placeholders).
*   **Session Management:** Add helpers or examples for managing user sessions after successful login.
*   **More Providers:** Add support for other popular OAuth providers.
*   **Configuration:** Improve configuration loading (e.g., from environment variables or config files).

## Security Considerations

The example code is intentionally simple and omits several production safety measures:

* **CSRF protection**: The example generates a state value but does not persist or verify it. Ensure you store the state and validate it on callbacks to prevent cross-site request forgery.
* **Apple ID token validation**: The library generates Apple client secrets but does not verify the returned ID token. Applications must validate the ID token using Apple's public keys before trusting user data.
* **Session management**: The example prints user information directly. In a real application you should create a session and manage cookies securely.

## Contributing

Contributions are welcome! To get started:

1. Format your code with `go fmt ./...` and run `go vet ./...`.
2. Ensure the project builds with `go build -v ./...`.
3. Although tests are currently missing, add unit tests for any new functionality and run `go test -v ./...`.
4. Open a pull request describing your changes.
