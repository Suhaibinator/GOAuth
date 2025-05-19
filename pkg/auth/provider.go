package auth

import "context"

// Provider defines the common interface implemented by all OAuth providers.
type Provider interface {
	// AuthURL generates the provider-specific authorization URL for the given state.
	AuthURL(ctx context.Context, state string) string
	// Login exchanges an authorization code for a User.
	Login(ctx context.Context, code string) (*User, error)
}
