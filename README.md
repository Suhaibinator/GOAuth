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
*   **Testing is currently missing.**

## Supported Providers (Partial List)

*   Google
*   GitHub
*   Discord
*   LinkedIn
*   Facebook
*   Apple

## Installation

```bash
go get github.com/Suhaibinator/GOAuth
```

## Basic Usage

See the example server in `examples/simple_server/main.go` for a demonstration of how to initialize the handler and set up login/callback routes.

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

## Improvements & Future Work

*   **Apple Sign In:** Add full ID token validation using Apple's public keys.
*   **Testing:** Add comprehensive unit and integration tests for all providers.
*   **Error Handling:** Refine error types and context.
*   **State Management:** Implement robust CSRF protection using state parameters (the example includes placeholders).
*   **Session Management:** Add helpers or examples for managing user sessions after successful login.
*   **More Providers:** Add support for other popular OAuth providers.
*   **Configuration:** Improve configuration loading (e.g., from environment variables or config files).

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
