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
	"golang.org/x/oauth2/facebook"
)

// ===== Facebook OAuth =====

// FacebookUserInfo represents the user information returned by the Facebook Graph API endpoint `/me`.
// The available fields depend on the scopes requested (e.g., `public_profile`, `email`).
// See: https://developers.facebook.com/docs/graph-api/reference/user/
type FacebookUserInfo struct {
	ID        string               `json:"id"`                   // The user's unique Facebook ID.
	Name      string               `json:"name"`                 // The user's full name.
	Email     string               `json:"email,omitempty"`      // The user's email address (requires 'email' scope).
	FirstName string               `json:"first_name,omitempty"` // The user's first name (requires 'public_profile').
	LastName  string               `json:"last_name,omitempty"`  // The user's last name (requires 'public_profile').
	Picture   *FacebookPictureData `json:"picture,omitempty"`    // Profile picture details (requires 'public_profile').
}

// FacebookPictureData is a wrapper structure for the profile picture data returned by the Graph API.
type FacebookPictureData struct {
	Data FacebookPicture `json:"data"` // Contains the actual picture details.
}

// FacebookPicture holds the URL and dimensions of the user's profile picture.
type FacebookPicture struct {
	URL          string `json:"url"`           // The URL of the profile picture.
	Height       int    `json:"height"`        // The height of the picture in pixels.
	Width        int    `json:"width"`         // The width of the picture in pixels.
	IsSilhouette bool   `json:"is_silhouette"` // Indicates if the picture is the default Facebook silhouette.
}

// facebookProvider implements the Provider interface for Facebook OAuth.
type facebookProvider struct {
	handler *OAuthHandler
}

func (f *facebookProvider) AuthURL(ctx context.Context, state string) string {
	return f.handler.GetFacebookAuthURL(ctx, state)
}

func (f *facebookProvider) Login(ctx context.Context, code string) (*User, error) {
	return f.handler.facebookLoginWithCode(ctx, code)
}

// fetchFacebookUserInfo retrieves the authenticated user's profile information from the Facebook Graph API (`/me`).
// It requires an authorized http.Client and appropriate scopes (e.g., `public_profile`, `email`).
// It requests specific fields like id, name, email, first_name, last_name, and picture.
func fetchFacebookUserInfo(ctx context.Context, client *http.Client) (*FacebookUserInfo, error) {
	// Construct the Graph API URL with desired fields. Requesting 'picture.type(large)' gets a larger image.
	reqURL := "https://graph.facebook.com/me?fields=id,name,email,first_name,last_name,picture.type(large)" // Request large picture type

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute user info request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var userInfo FacebookUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		bodyBytes, _ := io.ReadAll(resp.Body) // Read body again for debugging
		return nil, fmt.Errorf("failed to decode user info response: %w. Body: %s", err, string(bodyBytes))
	}
	return &userInfo, nil
}

// facebookLoginWithCode handles the final step of the Facebook OAuth flow.
// It exchanges the authorization code for an access token, fetches the user's profile
// information from the Facebook Graph API, and maps the data to the standardized User struct.
// Requires 'public_profile' and 'email' scopes for full user details.
// Returns ErrFailedToExchangeCode or ErrFailedToGetUserInfo on failure.
func (o *OAuthHandler) facebookLoginWithCode(ctx context.Context, code string) (*User, error) {
	logger := o.logEnricher(ctx, o.logger).Named("facebook_login")

	if o.facebookOAuthConfig == nil {
		logger.Error("Facebook OAuth config not initialized")
		return nil, errors.New("facebook OAuth config not initialized")
	}

	// Exchange the code for an OAuth token
	token, err := o.facebookOAuthConfig.Exchange(ctx, code)
	if err != nil {
		logger.Error("Failed to exchange code for token", zap.Error(err))
		return nil, ErrFailedToExchangeCode
	}

	if !token.Valid() {
		logger.Error("Received invalid token")
		return nil, ErrInvalidToken
	}

	// Use the token to get an HTTP client
	client := o.facebookOAuthConfig.Client(ctx, token)
	client.Timeout = 10 * time.Second // Set a timeout

	// Get the user info from Facebook's Graph API
	facebookUser, err := fetchFacebookUserInfo(ctx, client)
	if err != nil {
		logger.Error("Failed to get Facebook user info", zap.Error(err))
		return nil, ErrFailedToGetUserInfo
	}

	// Extract avatar URL
	avatarURL := ""
	if facebookUser.Picture != nil && !facebookUser.Picture.Data.IsSilhouette {
		avatarURL = facebookUser.Picture.Data.URL
	}

	// Create the standardized User struct.
	user := &User{
		Username:  facebookUser.Name, // Use the full name as the username.
		Email:     facebookUser.Email,
		AvatarUrl: avatarURL,
		FirstName: facebookUser.FirstName,
		LastName:  facebookUser.LastName,
	}

	logger.Info("Facebook login successful", zap.String("facebook_id", facebookUser.ID), zap.String("email", user.Email))
	return user, nil
}

// GetFacebookAuthURL generates the URL to redirect the user to for Facebook authentication.
// It includes the client ID, redirect URL, requested scopes ('public_profile', 'email'), and state.
func (o *OAuthHandler) GetFacebookAuthURL(ctx context.Context, state string) string {
	logger := o.logEnricher(ctx, o.logger).Named("facebook_auth_url")
	if o.facebookOAuthConfig == nil {
		logger.Error("Facebook OAuth config not initialized for GetFacebookAuthURL")
		return ""
	}
	// Use AuthCodeURL to generate the URL
	// Scopes are defined in the config
	return o.facebookOAuthConfig.AuthCodeURL(state) // Scopes are defined in the config.
}

// registerFacebookOAuth creates and stores the oauth2.Config for Facebook,
// using the credentials provided in the main OAuthConfig.
// It sets the 'public_profile' and 'email' scopes.
func (o *OAuthHandler) registerFacebookOAuth(ctx context.Context) (Provider, error) {
	logger := o.logEnricher(ctx, o.logger).Named("register_facebook")
	if o.config.FacebookOAuthClientID == "" || o.config.FacebookOAuthClientSecret == "" {
		logger.Error("Facebook OAuth client ID or secret missing during registration")
		return nil, errors.New("facebook OAuth client ID and secret are required")
	}

	// Define required scopes. Common ones are 'public_profile' and 'email'.
	scopes := []string{"public_profile", "email"}

	o.facebookOAuthConfig = &oauth2.Config{
		ClientID:     o.config.FacebookOAuthClientID,
		ClientSecret: o.config.FacebookOAuthClientSecret,
		RedirectURL:  o.config.FacebookOAuthRedirectURL,
		Scopes:       scopes,
		Endpoint:     facebook.Endpoint, // Facebook's OAuth2 endpoints
	}

	logger.Info("Facebook OAuth handler registered using golang.org/x/oauth2", zap.Strings("scopes", scopes))
	return &facebookProvider{handler: o}, nil
}
