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

// ===== Quran.Foundation OAuth =====

// QuranFoundationUserInfo represents basic OpenID Connect profile information.
// The fields correspond to the standard OIDC userinfo response.
type QuranFoundationUserInfo struct {
	Sub        string `json:"sub"`         // Subject identifier
	Name       string `json:"name"`        // Full name
	GivenName  string `json:"given_name"`  // First name
	FamilyName string `json:"family_name"` // Last name
	Email      string `json:"email"`       // Email address
	Picture    string `json:"picture"`     // Profile picture URL
}

// qfProvider implements the Provider interface for Quran.Foundation OAuth.
type qfProvider struct {
	handler *OAuthHandler
}

func (q *qfProvider) AuthURL(ctx context.Context, state string) string {
	return q.handler.GetQuranFoundationAuthURL(ctx, state)
}

func (q *qfProvider) Login(ctx context.Context, code string) (*User, error) {
	return q.handler.quranFoundationLoginWithCode(ctx, code)
}

// fetchQuranFoundationUserInfo retrieves the user's profile information from the
// Quran.Foundation userinfo endpoint using the provided HTTP client.
func fetchQuranFoundationUserInfo(ctx context.Context, client *http.Client) (*QuranFoundationUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://auth.quran.foundation/userinfo", nil)
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

	var userInfo QuranFoundationUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info response: %w", err)
	}
	return &userInfo, nil
}

// quranFoundationLoginWithCode completes the OAuth flow by exchanging the code
// for a token and retrieving user information.
func (o *OAuthHandler) quranFoundationLoginWithCode(ctx context.Context, code string) (*User, error) {
	logger := o.logEnricher(ctx, o.logger).Named("quranfoundation_login")

	if o.quranFoundationOAuthConfig == nil {
		logger.Error("Quran.Foundation OAuth config not initialized")
		return nil, errors.New("quran.foundation OAuth config not initialized")
	}

	token, err := o.quranFoundationOAuthConfig.Exchange(ctx, code)
	if err != nil {
		logger.Error("Failed to exchange code for token", zap.Error(err))
		return nil, ErrFailedToExchangeCode
	}

	if !token.Valid() {
		logger.Error("Received invalid token")
		return nil, errors.New("received invalid token from provider")
	}

	client := o.quranFoundationOAuthConfig.Client(ctx, token)
	client.Timeout = 10 * time.Second

	userInfo, err := fetchQuranFoundationUserInfo(ctx, client)
	if err != nil {
		logger.Error("Failed to get user info", zap.Error(err))
		return nil, ErrFailedToGetUserInfo
	}

	user := &User{
		Username:  userInfo.Name,
		Email:     userInfo.Email,
		AvatarUrl: userInfo.Picture,
		FirstName: userInfo.GivenName,
		LastName:  userInfo.FamilyName,
	}

	logger.Info("Quran.Foundation login successful", zap.String("email", user.Email))
	return user, nil
}

// GetQuranFoundationAuthURL builds the authorization URL for Quran.Foundation.
func (o *OAuthHandler) GetQuranFoundationAuthURL(ctx context.Context, state string) string {
	logger := o.logEnricher(ctx, o.logger).Named("quranfoundation_auth_url")
	if o.quranFoundationOAuthConfig == nil {
		logger.Error("Quran.Foundation OAuth config not initialized for GetAuthURL")
		return ""
	}
	return o.quranFoundationOAuthConfig.AuthCodeURL(state)
}

// registerQuranFoundationOAuth creates the oauth2.Config for Quran.Foundation.
// The endpoints are based on the provider's OpenID Connect implementation.
func (o *OAuthHandler) registerQuranFoundationOAuth(ctx context.Context) (Provider, error) {
	logger := o.logEnricher(ctx, o.logger).Named("register_quranfoundation")
	if o.config.QuranFoundationOAuthClientID == "" || o.config.QuranFoundationOAuthClientSecret == "" {
		logger.Error("Quran.Foundation OAuth client ID or secret missing during registration")
		return nil, errors.New("quran.foundation OAuth client ID and secret are required")
	}

	scopes := []string{"openid", "profile", "email"}

	o.quranFoundationOAuthConfig = &oauth2.Config{
		ClientID:     o.config.QuranFoundationOAuthClientID,
		ClientSecret: o.config.QuranFoundationOAuthClientSecret,
		RedirectURL:  o.config.QuranFoundationOAuthRedirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://auth.quran.foundation/authorize",
			TokenURL: "https://auth.quran.foundation/oauth/token",
		},
	}

	logger.Info("Quran.Foundation OAuth handler registered")
	return &qfProvider{handler: o}, nil
}
