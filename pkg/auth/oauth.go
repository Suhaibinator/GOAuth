package auth

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// User represents a standardized user profile obtained after successful OAuth authentication.
// Fields are populated based on the information available from the specific provider.
type User struct {
	Username  string `json:"username"`   // Best available username or login name
	Email     string `json:"email"`      // User's email address (if available and scope granted)
	AvatarUrl string `json:"avatar_url"` // URL to the user's profile picture (if available)
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"` // User's last name (if available)
}

// NewOAuthHandler creates and initializes a new OAuthHandler instance.
// It requires a zap logger and an OAuthConfig configuration.
// Returns nil if the provided config is nil.
func NewOAuthHandler(
	logger *zap.Logger,
	logEnricher func(ctx context.Context, logger *zap.Logger) *zap.Logger,
	config *OAuthConfig,
) *OAuthHandler {

	if config == nil {
		logger.Error("OAuth config is nil")
		return nil
	}

	// Create the handler
	handler := &OAuthHandler{
		logger:      logger.Named("oauth"),
		config:      *config,
		logEnricher: logEnricher,
	}
	// Register the OAuth providers based on the provided configuration
	handler.registerOAuthProviders(context.Background())
	return handler
}

// OAuthConfig holds the necessary configuration details for all supported OAuth providers.
// Client ID, Client Secret, and Redirect URL must be provided for each enabled provider.
type OAuthConfig struct {
	// Google OAuth Configuration
	GoogleOAuthClientID     string `json:"google_oauth_client_id" yaml:"google_oauth_client_id" toml:"google_oauth_client_id"`
	GoogleOAuthClientSecret string `json:"google_oauth_client_secret" yaml:"google_oauth_client_secret" toml:"google_oauth_client_secret"`
	GoogleOAuthRedirectURL  string `json:"google_oauth_redirect_url" yaml:"google_oauth_redirect_url" toml:"google_oauth_redirect_url"`

	// Facebook OAuth Configuration
	FacebookOAuthClientID     string `json:"facebook_oauth_client_id" yaml:"facebook_oauth_client_id" toml:"facebook_oauth_client_id"`
	FacebookOAuthClientSecret string `json:"facebook_oauth_client_secret" yaml:"facebook_oauth_client_secret" toml:"facebook_oauth_client_secret"`
	FacebookOAuthRedirectURL  string `json:"facebook_oauth_redirect_url" yaml:"facebook_oauth_redirect_url" toml:"facebook_oauth_redirect_url"`

	// Apple Sign In Configuration
	// Requires team ID, key ID and the private key used to sign the client secret JWT
	AppleOAuthClientID    string `json:"apple_oauth_client_id" yaml:"apple_oauth_client_id" toml:"apple_oauth_client_id"`
	AppleOAuthTeamID      string `json:"apple_oauth_team_id" yaml:"apple_oauth_team_id" toml:"apple_oauth_team_id"`
	AppleOAuthKeyID       string `json:"apple_oauth_key_id" yaml:"apple_oauth_key_id" toml:"apple_oauth_key_id"`
	AppleOAuthPrivateKey  string `json:"apple_oauth_private_key" yaml:"apple_oauth_private_key" toml:"apple_oauth_private_key"` // PEM encoded private key or path to .p8 file
	AppleOAuthRedirectURL string `json:"apple_oauth_redirect_url" yaml:"apple_oauth_redirect_url" toml:"apple_oauth_redirect_url"`

	// GitHub OAuth Configuration
	GitHubOAuthClientID     string `json:"github_oauth_client_id" yaml:"github_oauth_client_id" toml:"github_oauth_client_id"`
	GitHubOAuthClientSecret string `json:"github_oauth_client_secret" yaml:"github_oauth_client_secret" toml:"github_oauth_client_secret"`
	GitHubOAuthRedirectURL  string `json:"github_oauth_redirect_url" yaml:"github_oauth_redirect_url" toml:"github_oauth_redirect_url"`

	// LinkedIn OAuth Configuration
	LinkedInOAuthClientID     string `json:"linkedin_oauth_client_id" yaml:"linkedin_oauth_client_id" toml:"linkedin_oauth_client_id"`
	LinkedInOAuthClientSecret string `json:"linkedin_oauth_client_secret" yaml:"linkedin_oauth_client_secret" toml:"linkedin_oauth_client_secret"`
	LinkedInOAuthRedirectURL  string `json:"linkedin_oauth_redirect_url" yaml:"linkedin_oauth_redirect_url" toml:"linkedin_oauth_redirect_url"`

	// Discord OAuth Configuration
	DiscordOAuthClientID     string `json:"discord_oauth_client_id" yaml:"discord_oauth_client_id" toml:"discord_oauth_client_id"`
	DiscordOAuthClientSecret string `json:"discord_oauth_client_secret" yaml:"discord_oauth_client_secret" toml:"discord_oauth_client_secret"`
	DiscordOAuthRedirectURL  string `json:"discord_oauth_redirect_url" yaml:"discord_oauth_redirect_url" toml:"discord_oauth_redirect_url"`
	UseDiscordIdAsEmail      bool   `json:"use_discord_id_as_email" yaml:"use_discord_id_as_email" toml:"use_discord_id_as_email"` // If true, use Discord ID as email

	// Quran.Foundation OAuth Configuration
	QuranFoundationOAuthClientID     string `json:"quran_foundation_oauth_client_id" yaml:"quran_foundation_oauth_client_id" toml:"quran_foundation_oauth_client_id"`
	QuranFoundationOAuthClientSecret string `json:"quran_foundation_oauth_client_secret" yaml:"quran_foundation_oauth_client_secret" toml:"quran_foundation_oauth_client_secret"`
	QuranFoundationOAuthRedirectURL  string `json:"quran_foundation_oauth_redirect_url" yaml:"quran_foundation_oauth_redirect_url" toml:"quran_foundation_oauth_redirect_url"`
}

// Predefined errors related to the OAuth process.
var (
	// ErrInvalidOAuthCode indicates that the provided authorization code is invalid or expired.
	ErrInvalidOAuthCode = errors.New("invalid oauth code")
	// ErrFailedToGetUserInfo indicates an error occurred while fetching user details from the provider.
	ErrFailedToGetUserInfo = errors.New("failed to get user info")
	// ErrFailedToExchangeCode indicates an error occurred during the token exchange process.
	ErrFailedToExchangeCode = errors.New("failed to exchange code for token")
)

// OAuthHandler manages the configuration and logic for multiple OAuth providers.
type OAuthHandler struct {
	googleOAuthConfig          *oauth2.Config     // Configuration for Google OAuth.
	facebookOAuthConfig        *oauth2.Config     // Configuration for Facebook OAuth.
	appleOauthHandler          *AppleOauthHandler // Custom handler for Apple Sign In.
	githubOAuthConfig          *oauth2.Config     // Configuration for GitHub OAuth.
	linkedInOAuthConfig        *oauth2.Config     // Configuration for LinkedIn OAuth.
	discordOAuthConfig         *oauth2.Config     // Configuration for Discord OAuth.
	quranFoundationOAuthConfig *oauth2.Config
	// Configuration for Quran.Foundation OAuth.
	logger      *zap.Logger                                               // Shared logger instance.
	logEnricher func(ctx context.Context, logger *zap.Logger) *zap.Logger // Function to enrich logs with trace ID.

	config OAuthConfig // Stores the initial configuration.

	providers map[OAuthProvider]Provider
}

// RegisterOAuthProviders iterates through the OAuthConfig and initializes
// the corresponding provider handlers (oauth2.Config or custom handlers)
// if their ClientID is configured. Logs warnings for registration failures.
func (h *OAuthHandler) registerOAuthProviders(ctx context.Context) {
	// Initialize OAuth handlers based on configuration.
	// Use logger associated with the handler (h.logger).
	logger := h.logger.Named("registration") // Create a sub-logger for registration process

	h.providers = make(map[OAuthProvider]Provider)

	if h.config.GoogleOAuthClientID != "" {
		if p, err := h.registerGoogleOAuth(ctx); err != nil {
			logger.Warn("Failed to register Google OAuth", zap.Error(err))
		} else {
			h.providers[GoogleOAuthProvider] = p
			logger.Info("Google OAuth registered successfully")
		}
	} else {
		logger.Info("Google OAuth registration skipped (missing config)")
	}

	if h.config.FacebookOAuthClientID != "" {
		if p, err := h.registerFacebookOAuth(ctx); err != nil {
			logger.Warn("Failed to register Facebook OAuth", zap.Error(err))
		} else {
			h.providers[FacebookOAuthProvider] = p
			logger.Info("Facebook OAuth registered successfully")
		}
	} else {
		logger.Info("Facebook OAuth registration skipped (missing config)")
	}

	if h.config.AppleOAuthClientID != "" {
		if p, err := h.registerAppleOAuth(ctx); err != nil {
			logger.Warn("Failed to register Apple OAuth", zap.Error(err))
		} else {
			h.providers[AppleOAuthProvider] = p
			logger.Info("Apple OAuth registered successfully (check secret handling)")
		}
	} else {
		logger.Info("Apple OAuth registration skipped (missing config)")
	}

	if h.config.GitHubOAuthClientID != "" {
		if p, err := h.registerGitHubOAuth(ctx); err != nil {
			logger.Warn("Failed to register GitHub OAuth", zap.Error(err))
		} else {
			h.providers[GitHubOAuthProvider] = p
			logger.Info("GitHub OAuth registered successfully")
		}
	} else {
		logger.Info("GitHub OAuth registration skipped (missing config)")
	}

	if h.config.DiscordOAuthClientID != "" {
		if p, err := h.registerDiscordOAuth(ctx); err != nil {
			logger.Warn("Failed to register Discord OAuth", zap.Error(err))
		} else {
			h.providers[DiscordOAuthProvider] = p
			logger.Info("Discord OAuth registered successfully")
		}
	} else {
		logger.Info("Discord OAuth registration skipped (missing config)")
	}

	if h.config.QuranFoundationOAuthClientID != "" {
		if p, err := h.registerQuranFoundationOAuth(ctx); err != nil {
			logger.Warn("Failed to register Quran.Foundation OAuth", zap.Error(err))
		} else {
			h.providers[QuranFoundationOAuthProvider] = p
			logger.Info("Quran.Foundation OAuth registered successfully")
		}
	} else {
		logger.Info("Quran.Foundation OAuth registration skipped (missing config)")
	}

	if h.config.LinkedInOAuthClientID != "" {
		if p, err := h.registerLinkedInOAuth(ctx); err != nil {
			logger.Warn("Failed to register LinkedIn OAuth", zap.Error(err))
		} else {
			h.providers[LinkedInOAuthProvider] = p
			logger.Info("LinkedIn OAuth registered successfully")
		}
	} else {
		logger.Info("LinkedIn OAuth registration skipped (missing config)")
	}

}

type OAuthProvider int

const (
	GoogleOAuthProvider OAuthProvider = iota
	FacebookOAuthProvider
	AppleOAuthProvider
	GitHubOAuthProvider
	LinkedInOAuthProvider
	DiscordOAuthProvider
	QuranFoundationOAuthProvider
)

func (h *OAuthHandler) LoginWithCode(ctx context.Context, provider OAuthProvider, code string) (*User, error) {
	logger := h.logEnricher(ctx, h.logger)

	p, ok := h.providers[provider]
	if !ok {
		logger.Error("Invalid OAuth provider")
		return nil, errors.New("invalid OAuth provider")
	}

	return p.Login(ctx, code)
}

// RefreshToken attempts to exchange a refresh token for a new access token for the
// specified provider. Only providers that have been configured will be able to
// refresh tokens. The returned oauth2.Token will contain the new access token
// and potentially a new refresh token if the provider rotates them.
func (h *OAuthHandler) RefreshToken(ctx context.Context, provider OAuthProvider, refreshToken string) (*oauth2.Token, error) {
	logger := h.logEnricher(ctx, h.logger).Named("refresh_token")

	if refreshToken == "" {
		logger.Error("refresh token is empty")
		return nil, errors.New("refresh token is empty")
	}

	switch provider {
	case GoogleOAuthProvider:
		return h.refreshWithConfig(ctx, h.googleOAuthConfig, refreshToken)
	case FacebookOAuthProvider:
		return h.refreshWithConfig(ctx, h.facebookOAuthConfig, refreshToken)
	case GitHubOAuthProvider:
		return h.refreshWithConfig(ctx, h.githubOAuthConfig, refreshToken)
	case LinkedInOAuthProvider:
		return h.refreshWithConfig(ctx, h.linkedInOAuthConfig, refreshToken)
	case DiscordOAuthProvider:
		return h.refreshWithConfig(ctx, h.discordOAuthConfig, refreshToken)
	case QuranFoundationOAuthProvider:
		return h.refreshWithConfig(ctx, h.quranFoundationOAuthConfig, refreshToken)
	case AppleOAuthProvider:
		if h.appleOauthHandler == nil {
			logger.Error("Apple OAuth handler not initialized")
			return nil, errors.New("apple OAuth handler not initialized")
		}
		return h.appleOauthHandler.Refresh(ctx, refreshToken)
	default:
		logger.Error("Invalid OAuth provider for refresh")
		return nil, errors.New("invalid OAuth provider")
	}
}

// refreshWithConfig performs a token refresh using a standard oauth2.Config.
func (h *OAuthHandler) refreshWithConfig(ctx context.Context, conf *oauth2.Config, refreshToken string) (*oauth2.Token, error) {
	if conf == nil {
		return nil, errors.New("oauth config not initialized")
	}
	ts := conf.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken, Expiry: time.Now().Add(-time.Hour)})
	tok, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return tok, nil
}

// Stop performs any cleanup needed for the OAuthHandler
func (h *OAuthHandler) Stop() {
	// No explicit resources like database connections to close here typically.
	// If HTTP clients had specific cleanup needs, they could be handled here.
	h.logger.Info("OAuthHandler stopped.") // Log when the handler stops.
}
