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
)

// ===== Okta OAuth =====

// OktaUserInfo represents the user information returned by Okta's userinfo endpoint
// (https://{domain}/oauth2/v1/userinfo).
type OktaUserInfo struct {
	Sub               string `json:"sub"`                         // The user's unique Okta ID.
	Name              string `json:"name"`                        // The user's full name.
	GivenName         string `json:"given_name"`                  // The user's first name.
	FamilyName        string `json:"family_name"`                 // The user's last name.
	MiddleName        string `json:"middle_name,omitempty"`       // The user's middle name.
	Nickname          string `json:"nickname,omitempty"`          // The user's nickname.
	PreferredUsername string `json:"preferred_username"`          // The user's preferred username.
	Profile           string `json:"profile,omitempty"`           // URL of the user's profile page.
	Picture           string `json:"picture,omitempty"`           // URL of the user's profile picture.
	Website           string `json:"website,omitempty"`           // URL of the user's website.
	Email             string `json:"email"`                       // The user's email address.
	EmailVerified     bool   `json:"email_verified"`              // Whether the email address is verified.
	Gender            string `json:"gender,omitempty"`            // The user's gender.
	Birthdate         string `json:"birthdate,omitempty"`         // The user's birthdate.
	Zoneinfo          string `json:"zoneinfo,omitempty"`          // The user's time zone.
	Locale            string `json:"locale,omitempty"`            // The user's locale.
	PhoneNumber       string `json:"phone_number,omitempty"`      // The user's phone number.
	PhoneVerified     bool   `json:"phone_number_verified"`       // Whether the phone number is verified.
	Address           string `json:"address,omitempty"`           // The user's address.
	UpdatedAt         int64  `json:"updated_at"`                  // When the user's info was last updated.
}

// oktaProvider implements the Provider interface for Okta OAuth.
type oktaProvider struct {
	handler *OAuthHandler
}

func (o *oktaProvider) AuthURL(ctx context.Context, state string) string {
	return o.handler.GetOktaAuthURL(ctx, state)
}

func (o *oktaProvider) Login(ctx context.Context, code string) (*User, error) {
	return o.handler.oktaLoginWithCode(ctx, code)
}

// fetchOktaUserInfo retrieves the authenticated user's profile information from Okta's userinfo endpoint.
// It requires an authorized http.Client.
func fetchOktaUserInfo(ctx context.Context, client *http.Client, domain string) (*OktaUserInfo, error) {
	userInfoURL := fmt.Sprintf("https://%s/oauth2/v1/userinfo", domain)
	
	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
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

	var userInfo OktaUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info response: %w", err)
	}
	return &userInfo, nil
}

// oktaLoginWithCode handles the final step of the Okta OAuth flow.
// It exchanges the authorization code for an access token, fetches the user's profile
// information from Okta's userinfo endpoint, and maps it to the standardized User struct.
// Returns ErrFailedToExchangeCode or ErrFailedToGetUserInfo on failure.
func (o *OAuthHandler) oktaLoginWithCode(ctx context.Context, code string) (*User, error) {
	logger := o.logEnricher(ctx, o.logger).Named("okta_login")

	if o.oktaOAuthConfig == nil {
		logger.Error("Okta OAuth config not initialized")
		return nil, errors.New("okta OAuth config not initialized")
	}

	// Exchange the code for an OAuth token
	token, err := o.oktaOAuthConfig.Exchange(ctx, code)
	if err != nil {
		logger.Error("Failed to exchange code for token", zap.Error(err))
		return nil, ErrFailedToExchangeCode
	}

	if !token.Valid() {
		logger.Error("Received invalid token")
		return nil, ErrInvalidToken
	}

	// Use the token to get an HTTP client
	client := o.oktaOAuthConfig.Client(ctx, token)
	client.Timeout = 15 * time.Second // Set a timeout for Okta API calls

	// Get the user info from Okta's userinfo endpoint
	oktaUser, err := fetchOktaUserInfo(ctx, client, o.config.OktaOAuthDomain)
	if err != nil {
		logger.Error("Failed to get Okta user info", zap.Error(err))
		return nil, ErrFailedToGetUserInfo
	}

	// Create a standardized User struct from the Okta user info
	username := oktaUser.Name
	if username == "" {
		username = oktaUser.PreferredUsername // Fallback to preferred username if full name is not available
	}

	user := &User{
		Username:  username,
		Email:     oktaUser.Email,
		AvatarUrl: oktaUser.Picture,
		FirstName: oktaUser.GivenName,
		LastName:  oktaUser.FamilyName,
	}

	logger.Info("Okta login successful", zap.String("okta_sub", oktaUser.Sub), zap.String("email", user.Email))
	return user, nil
}

// GetOktaAuthURL generates the URL to redirect the user to for Okta authentication.
// It includes the necessary client ID, redirect URL, scopes, and state parameter.
func (o *OAuthHandler) GetOktaAuthURL(ctx context.Context, state string) string {
	logger := o.logEnricher(ctx, o.logger).Named("okta_auth_url")
	if o.oktaOAuthConfig == nil {
		logger.Error("Okta OAuth config not initialized for GetOktaAuthURL")
		return ""
	}
	// Use AuthCodeURL to generate the URL
	return o.oktaOAuthConfig.AuthCodeURL(state)
}

// registerOktaOAuth creates and stores the oauth2.Config for Okta,
// using the credentials provided in the main OAuthConfig.
// It sets the standard OpenID Connect scopes ('openid', 'profile', 'email').
func (o *OAuthHandler) registerOktaOAuth(ctx context.Context) (Provider, error) {
	logger := o.logEnricher(ctx, o.logger).Named("register_okta")
	if o.config.OktaOAuthClientID == "" || o.config.OktaOAuthClientSecret == "" {
		logger.Error("Okta OAuth client ID or secret missing during registration")
		return nil, errors.New("okta OAuth client ID and secret are required")
	}

	if o.config.OktaOAuthDomain == "" {
		logger.Error("Okta OAuth domain missing during registration")
		return nil, errors.New("okta OAuth domain is required")
	}

	// Create OAuth2 endpoints using the Okta domain
	authURL := fmt.Sprintf("https://%s/oauth2/v1/authorize", o.config.OktaOAuthDomain)
	tokenURL := fmt.Sprintf("https://%s/oauth2/v1/token", o.config.OktaOAuthDomain)

	o.oktaOAuthConfig = &oauth2.Config{
		ClientID:     o.config.OktaOAuthClientID,
		ClientSecret: o.config.OktaOAuthClientSecret,
		RedirectURL:  o.config.OktaOAuthRedirectURL,
		Scopes:       []string{"openid", "profile", "email"}, // Standard OpenID Connect scopes
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}

	logger.Info("Okta OAuth handler registered", zap.String("domain", o.config.OktaOAuthDomain))
	return &oktaProvider{handler: o}, nil
}