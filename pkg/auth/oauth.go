package auth

import (
	"context"
	"errors"

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
	GoogleOAuthClientID     string
	GoogleOAuthClientSecret string
	GoogleOAuthRedirectURL  string

	// Facebook OAuth Configuration

	FacebookOAuthClientID     string
	FacebookOAuthClientSecret string
	FacebookOAuthRedirectURL  string

	// Apple Sign In Configuration (Note: Secret might be complex, e.g., key file path)
	AppleOAuthClientID     string
	AppleOAuthClientSecret string // Or Key ID / Team ID / Key File Path depending on implementation
	AppleOAuthRedirectURL  string

	// GitHub OAuth Configuration

	GitHubOAuthClientID     string
	GitHubOAuthClientSecret string
	GitHubOAuthRedirectURL  string

	// LinkedIn OAuth Configuration
	LinkedInOAuthClientID     string
	LinkedInOAuthClientSecret string
	LinkedInOAuthRedirectURL  string

	// Discord OAuth Configuration

	DiscordOAuthClientID     string
	DiscordOAuthClientSecret string
	DiscordOAuthRedirectURL  string

	// TraceIdKey is the key used to extract the trace ID from the context for logging.
	TraceIdKey string
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
	googleOAuthConfig   *oauth2.Config                                            // Configuration for Google OAuth.
	facebookOAuthConfig *oauth2.Config                                            // Configuration for Facebook OAuth.
	appleOauthHandler   *AppleOauthHandler                                        // Custom handler for Apple Sign In.
	githubOAuthConfig   *oauth2.Config                                            // Configuration for GitHub OAuth.
	linkedInOAuthConfig *oauth2.Config                                            // Configuration for LinkedIn OAuth.
	discordOAuthConfig  *oauth2.Config                                            // Configuration for Discord OAuth.
	logger              *zap.Logger                                               // Shared logger instance.
	logEnricher         func(ctx context.Context, logger *zap.Logger) *zap.Logger // Function to enrich logs with trace ID.

	config OAuthConfig // Stores the initial configuration.
}

// RegisterOAuthProviders iterates through the OAuthConfig and initializes
// the corresponding provider handlers (oauth2.Config or custom handlers)
// if their ClientID is configured. Logs warnings for registration failures.
func (h *OAuthHandler) registerOAuthProviders(ctx context.Context) {
	// Initialize OAuth handlers based on configuration.
	// Use logger associated with the handler (h.logger).
	logger := h.logger.Named("registration") // Create a sub-logger for registration process

	if h.config.GoogleOAuthClientID != "" {
		if err := h.registerGoogleOAuth(ctx); err != nil {
			logger.Warn("Failed to register Google OAuth", zap.Error(err))
		} else {
			logger.Info("Google OAuth registered successfully")
		}
	} else {
		logger.Info("Google OAuth registration skipped (missing config)")
	}

	if h.config.FacebookOAuthClientID != "" {
		if err := h.registerFacebookOAuth(ctx); err != nil {
			logger.Warn("Failed to register Facebook OAuth", zap.Error(err))
		} else {
			logger.Info("Facebook OAuth registered successfully")
		}
	} else {
		logger.Info("Facebook OAuth registration skipped (missing config)")
	}

	if h.config.AppleOAuthClientID != "" {
		// Apple registration might require more complex setup (JWT generation)
		if err := h.registerAppleOAuth(ctx); err != nil {
			logger.Warn("Failed to register Apple OAuth", zap.Error(err))
		} else {
			logger.Info("Apple OAuth registered successfully (check secret handling)")
		}
	} else {
		logger.Info("Apple OAuth registration skipped (missing config)")
	}

	if h.config.GitHubOAuthClientID != "" {
		if err := h.registerGitHubOAuth(ctx); err != nil {
			logger.Warn("Failed to register GitHub OAuth", zap.Error(err))
		} else {
			logger.Info("GitHub OAuth registered successfully")
		}
	} else {
		logger.Info("GitHub OAuth registration skipped (missing config)")
	}

	if h.config.DiscordOAuthClientID != "" {
		if err := h.registerDiscordOAuth(ctx); err != nil {
			logger.Warn("Failed to register Discord OAuth", zap.Error(err))
		} else {
			logger.Info("Discord OAuth registered successfully")
		}
	} else {
		logger.Info("Discord OAuth registration skipped (missing config)")
	}

	if h.config.LinkedInOAuthClientID != "" {
		if err := h.registerLinkedInOAuth(ctx); err != nil {
			logger.Warn("Failed to register LinkedIn OAuth", zap.Error(err))
		} else {
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
	DiscordIdOAuthProvider
)

func (h *OAuthHandler) LoginWithCode(ctx context.Context, provider OAuthProvider, code string) (*User, error) {
	logger := h.logEnricher(ctx, h.logger)

	switch provider {
	case GoogleOAuthProvider:
		return h.googleLoginWithCode(ctx, code)
	case FacebookOAuthProvider:
		return h.facebookLoginWithCode(ctx, code)
	case AppleOAuthProvider:
		logger.Warn("Apple OAuth provider is not fully implemented")
		return h.appleLoginWithCode(ctx, code)
	case GitHubOAuthProvider:
		return h.gitHubLoginWithCode(ctx, code)
	case LinkedInOAuthProvider:
		return h.linkedInLoginWithCode(ctx, code)
	case DiscordOAuthProvider:
		return h.discordLoginWithCode(ctx, code)
	case DiscordIdOAuthProvider:
		return h.discordIdLoginWithCode(ctx, code)
	default:
		logger.Error("Invalid OAuth provider")
		return nil, errors.New("invalid OAuth provider")
	}
}

// Stop performs any cleanup needed for the OAuthHandler
func (h *OAuthHandler) Stop() {
	// No explicit resources like database connections to close here typically.
	// If HTTP clients had specific cleanup needs, they could be handled here.
	h.logger.Info("OAuthHandler stopped.") // Log when the handler stops.
}
