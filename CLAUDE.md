# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
GOAuth is a Go package that provides OAuth 2.0 handlers for social login providers (Google, GitHub, Discord, LinkedIn, Facebook, Apple, Quran.Foundation, Okta). It abstracts OAuth flow complexity behind a consistent interface.

## Commands
- **Build**: `go build -v ./...`
- **Test**: `go test -v ./...` (Note: No tests currently exist)
- **Run example**: `go run examples/simple_server/main.go`

## Architecture
The codebase follows a provider pattern where each OAuth provider implements a common interface:

```go
type Provider interface {
    AuthURL(state string) string
    Login(ctx context.Context, callbackParams CallbackParams) (*User, error)
}
```

Key components:
- `OAuthHandler` in `pkg/auth/oauth.go` - Central manager for all providers
- Individual providers in `pkg/auth/*.go` - Each implements the Provider interface
- Most providers leverage `golang.org/x/oauth2` except Apple (custom JWT implementation)

All providers map user data to a unified `User` struct for consistency.

## Important Implementation Notes
1. **Apple OAuth** requires special handling with JWT client secrets (see `pkg/auth/apple.go`)
2. **No tests exist** - When adding features, consider creating the testing infrastructure
3. **Security gaps**: Apple ID token validation and CSRF protection need improvement
4. **Token refresh** is supported via `RefreshToken` method
5. Logging uses zap with trace ID support via context