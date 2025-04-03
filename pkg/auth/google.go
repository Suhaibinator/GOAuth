package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// ===== Google OAuth =====

// GoogleUserInfo represents the user information returned by Google's userinfo endpoint
// (https://www.googleapis.com/oauth2/v2/userinfo).
type GoogleUserInfo struct {
	ID            string `json:"id"`             // The user's unique Google ID.
	Email         string `json:"email"`          // The user's email address.
	VerifiedEmail bool   `json:"verified_email"` // Whether Google has verified the email address.
	Name          string `json:"name"`           // The user's full name.
	GivenName     string `json:"given_name"`     // The user's first name.
	FamilyName    string `json:"family_name"`    // The user's last name.
	Picture       string `json:"picture"`        // URL of the user's profile picture.
	Locale        string `json:"locale"`         // The user's locale (e.g., "en").
}

// googleLoginWithCode handles the final step of the Google OAuth flow.
// It exchanges the authorization code received from the frontend for an access token,
// fetches the user's profile information from Google's userinfo endpoint,
// and maps it to the standardized User struct.
// Returns ErrFailedToExchangeCode or ErrFailedToGetUserInfo on failure.
func (o *OAuthHandler) googleLoginWithCode(ctx context.Context, code string) (*User, error) {
	logger := withTraceID(ctx, o.logger, o.config.TraceIdKey).Named("google_login")

	if o.googleOAuthConfig == nil {
		logger.Error("Google OAuth config not initialized")
		return nil, errors.New("google OAuth config not initialized")
	}

	// Exchange the code for an OAuth token
	token, err := o.googleOAuthConfig.Exchange(ctx, code)
	if err != nil {
		logger.Error("Failed to exchange code for token", zap.Error(err))
		// Check if the error is specifically an invalid code error
		// Note: oauth2 library might return a generic error, inspect if needed
		// For now, map to our generic exchange error
		return nil, ErrFailedToExchangeCode
	}

	if !token.Valid() {
		logger.Error("Received invalid token")
		return nil, errors.New("received invalid token from provider")
	}

	// Use the token to get an HTTP client
	client := o.googleOAuthConfig.Client(ctx, token)
	client.Timeout = 10 * time.Second // Set a timeout

	// Get the user info from Google's userinfo endpoint
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		logger.Error("Failed to request user info", zap.Error(err))
		return nil, ErrFailedToGetUserInfo
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		logger.Error("Failed to get user info, non-OK status",
			zap.Int("status_code", resp.StatusCode),
			zap.String("response_body", string(bodyBytes)))
		return nil, ErrFailedToGetUserInfo
	}

	var googleUser GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		logger.Error("Failed to decode user info response", zap.Error(err))
		return nil, ErrFailedToGetUserInfo
	}

	// Create a standardized User struct from the Google user info.
	user := &User{
		Username:  googleUser.Name, // Using full name as username. Consider alternatives if needed.
		Email:     googleUser.Email,
		AvatarUrl: googleUser.Picture,
		FirstName: googleUser.GivenName,
		LastName:  googleUser.FamilyName,
	}

	logger.Info("Google login successful", zap.String("email", user.Email))
	return user, nil
}

// GetGoogleAuthURL generates the URL to redirect the user to for Google authentication.
// It includes the necessary client ID, redirect URL, scopes, and state parameter.
// Requests offline access to potentially receive a refresh token.
func (o *OAuthHandler) GetGoogleAuthURL(ctx context.Context, state string) string {
	logger := withTraceID(ctx, o.logger, o.config.TraceIdKey).Named("google_auth_url")
	if o.googleOAuthConfig == nil {
		logger.Error("Google OAuth config not initialized for GetGoogleAuthURL")
		return ""
	}
	// Request "openid", "email", and "profile" scopes
	// Use AuthCodeURL to generate the URL
	return o.googleOAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce) // Request refresh token if possible
}

// registerGoogleOAuth creates and stores the oauth2.Config for Google,
// using the credentials provided in the main OAuthConfig.
// It sets the standard "openid", "email", and "profile" scopes.
func (o *OAuthHandler) registerGoogleOAuth(ctx context.Context) error {
	logger := withTraceID(ctx, o.logger, o.config.TraceIdKey).Named("register_google")
	if o.config.GoogleOAuthClientID == "" || o.config.GoogleOAuthClientSecret == "" {
		logger.Error("Google OAuth client ID or secret missing during registration")
		return errors.New("google OAuth client ID and secret are required")
	}

	o.googleOAuthConfig = &oauth2.Config{
		ClientID:     o.config.GoogleOAuthClientID,
		ClientSecret: o.config.GoogleOAuthClientSecret,
		RedirectURL:  o.config.GoogleOAuthRedirectURL,
		Scopes:       []string{"openid", "email", "profile"}, // Standard scopes
		Endpoint:     google.Endpoint,                        // Google's OAuth2 endpoints
	}

	logger.Info("Google OAuth handler registered using golang.org/x/oauth2")
	return nil
}
