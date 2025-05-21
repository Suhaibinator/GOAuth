package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
	// Discord endpoint will be defined manually
)

// ErrDiscordEmailEmpty is returned when the Discord user's email is empty,
// which might happen if the 'email' scope was not requested or granted,
// or if the user does not have a primary email set on their Discord account.
var ErrDiscordEmailEmpty = errors.New("discord user email is empty, 'email' scope may be missing or not granted")

// ===== Discord OAuth =====

// DiscordUserInfo represents the user information returned by the Discord API endpoint `/users/@me`.
// See: https://discord.com/developers/docs/resources/user#user-object
type DiscordUserInfo struct {
	ID            string `json:"id"`            // The user's unique ID.
	Username      string `json:"username"`      // The user's username (not unique across the platform).
	Discriminator string `json:"discriminator"` // The 4-digit discord-tag (being phased out).
	Avatar        string `json:"avatar"`        // The user's avatar hash.
	Email         string `json:"email"`         // The user's email (requires 'email' scope).
	Verified      bool   `json:"verified"`      // Whether the email on this account has been verified (requires 'email' scope).
	MFAEnabled    bool   `json:"mfa_enabled"`   // Whether the user has two factor enabled on their account.
	Locale        string `json:"locale"`        // The user's chosen language option.
	Flags         int    `json:"flags"`         // The flags on a user's account.
	PremiumType   int    `json:"premium_type"`  // The type of Nitro subscription on a user's account.
	PublicFlags   int    `json:"public_flags"`  // The public flags on a user's account.
	GlobalName    string `json:"global_name"`   // The user's display name, if set. For bots, this is the application name.
}

// discordProvider implements the Provider interface for Discord OAuth.
type discordProvider struct {
	handler *OAuthHandler
}

func (d *discordProvider) AuthURL(ctx context.Context, state string) string {
	return d.handler.GetDiscordAuthURL(ctx, state)
}

func (d *discordProvider) Login(ctx context.Context, code string) (*User, error) {
	return d.handler.discordLoginWithCode(ctx, code)
}

// getDiscordAvatarURL constructs the full URL for a user's avatar given their ID and avatar hash.
// Returns an empty string if the avatar hash is empty (user might have default avatar).
// See: https://discord.com/developers/docs/reference#image-formatting
func getDiscordAvatarURL(userID, avatarHash string) string {
	if avatarHash == "" {
		// Discord provides default avatars based on discriminator or ID, but constructing
		// that URL is more complex. Returning empty is simpler for now.
		// For simplicity, return empty or a placeholder
		return ""
	}
	// Example: https://cdn.discordapp.com/avatars/USER_ID/AVATAR_HASH.png
	return fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", userID, avatarHash)
}

// fetchDiscordUserInfo retrieves the authenticated user's profile information from the Discord API (`/users/@me`).
// It requires an authorized http.Client (obtained via OAuth token).
func fetchDiscordUserInfo(ctx context.Context, client *http.Client) (*DiscordUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/users/@me", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}
	// No specific Accept header needed usually, relies on Authorization

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute user info request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var userInfo DiscordUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info response: %w", err)
	}
	return &userInfo, nil
}

// _discordLoginCore is a helper function that handles the common logic for Discord OAuth flows.
// It exchanges the code for a token, fetches user info, and constructs a User struct.
// The getEmailFunc parameter allows customization of how the email is derived from DiscordUserInfo.
func (o *OAuthHandler) _discordLoginCore(ctx context.Context, code string, getEmailFunc func(logger *zap.Logger, userInfo *DiscordUserInfo) (string, error)) (*User, error) {
	logger := o.logEnricher(ctx, o.logger).Named("discord_login_core")

	if o.discordOAuthConfig == nil {
		logger.Error("Discord OAuth config not initialized")
		return nil, errors.New("discord OAuth config not initialized")
	}

	// Exchange the code for an OAuth token
	token, err := o.discordOAuthConfig.Exchange(ctx, code)
	if err != nil {
		logger.Error("Failed to exchange code for token", zap.Error(err))
		return nil, ErrFailedToExchangeCode
	}

	if !token.Valid() {
		logger.Error("Received invalid token")
		return nil, errors.New("received invalid token from provider")
	}

	// Use the token to get an HTTP client
	client := o.discordOAuthConfig.Client(ctx, token)
	client.Timeout = 10 * time.Second // Set a timeout

	// Get the user info from Discord's API
	discordUser, err := fetchDiscordUserInfo(ctx, client)
	if err != nil {
		logger.Error("Failed to get Discord user info", zap.Error(err))
		return nil, ErrFailedToGetUserInfo
	}

	// Determine the best username (GlobalName or fallback to Username)
	username := discordUser.GlobalName
	if username == "" {
		username = discordUser.Username // Fallback to the older username if GlobalName isn't set.
	}

	email, err := getEmailFunc(logger, discordUser)
	if err != nil {
		// The getEmailFunc is responsible for logging specific reasons for the error.
		return nil, err
	}

	// Create the standardized User struct.
	user := &User{
		Username:  username,
		Email:     email, // Use the email from getEmailFunc
		AvatarUrl: getDiscordAvatarURL(discordUser.ID, discordUser.Avatar),
		// Discord doesn't provide separate first/last names.
	}

	logger.Info("Discord login successful", zap.String("discord_id", discordUser.ID), zap.String("discord_username", user.Username), zap.String("email", user.Email))
	return user, nil
}

// discordLoginWithCode handles the final step of the Discord OAuth flow.
// It exchanges the authorization code for an access token, fetches the user's profile
// information from the Discord API, and maps it to the standardized User struct.
// Requires 'identify' and optionally 'email' scopes.
// Returns ErrFailedToExchangeCode, ErrFailedToGetUserInfo, or ErrDiscordEmailEmpty on failure.
func (o *OAuthHandler) discordLoginWithCode(ctx context.Context, code string) (*User, error) {
	return o._discordLoginCore(ctx, code, func(logger *zap.Logger, userInfo *DiscordUserInfo) (string, error) {
		if userInfo.Email == "" {
			logger.Error("Discord user email is empty. The 'email' scope might be missing, not granted by the user, or the user may not have a primary email set on their Discord account.",
				zap.String("discord_id", userInfo.ID))
			return "", ErrDiscordEmailEmpty
		}
		return userInfo.Email, nil
	})
}

func (o *OAuthHandler) discordIdLoginWithCode(ctx context.Context, code string) (*User, error) {
	return o._discordLoginCore(ctx, code, func(logger *zap.Logger, userInfo *DiscordUserInfo) (string, error) {
		// This flow constructs an email from the ID, so it doesn't depend on userInfo.Email
		return userInfo.ID + "@discordid.com", nil
	})
}

// GetDiscordAuthURL generates the URL to redirect the user to for Discord authentication.
// It includes the client ID, redirect URL, requested scopes ('identify', 'email'), and state.
func (o *OAuthHandler) GetDiscordAuthURL(ctx context.Context, state string) string {
	logger := o.logEnricher(ctx, o.logger).Named("discord_auth_url")
	if o.discordOAuthConfig == nil {
		logger.Error("Discord OAuth config not initialized for GetDiscordAuthURL")
		return ""
	}
	// Use AuthCodeURL to generate the URL
	// Scopes are defined in the config
	return o.discordOAuthConfig.AuthCodeURL(state) // Scopes are defined in the config.
}

// registerDiscordOAuth creates and stores the oauth2.Config for Discord,
// using the credentials provided in the main OAuthConfig.
// It manually defines the Discord API endpoints and sets the 'identify' and 'email' scopes.
func (o *OAuthHandler) registerDiscordOAuth(ctx context.Context) (Provider, error) {
	logger := o.logEnricher(ctx, o.logger).Named("register_discord")
	if o.config.DiscordOAuthClientID == "" || o.config.DiscordOAuthClientSecret == "" {
		logger.Error("Discord OAuth client ID or secret missing during registration")
		return nil, errors.New("discord OAuth client ID and secret are required")
	}

	o.discordOAuthConfig = &oauth2.Config{
		ClientID:     o.config.DiscordOAuthClientID,
		ClientSecret: o.config.DiscordOAuthClientSecret,
		RedirectURL:  o.config.DiscordOAuthRedirectURL,
		// Common Discord scopes: identify (basic user info), email
		Scopes: []string{"identify", "email"},
		Endpoint: oauth2.Endpoint{ // Manually define Discord endpoints
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	}

	logger.Info("Discord OAuth handler registered using manually defined endpoint")
	return &discordProvider{handler: o}, nil
}
