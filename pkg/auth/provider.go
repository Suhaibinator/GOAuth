package auth

import "context"

// Provider defines the common interface implemented by all OAuth providers.
type Provider interface {
	// AuthURL generates the provider-specific authorization URL for the given state.
	AuthURL(ctx context.Context, state string) string
	// Login exchanges an authorization code using the exact redirect URI from
	// authorization. Callers must validate and bind this URI to the OAuth attempt.
	Login(ctx context.Context, code, redirectURI string) (*User, error)
}
