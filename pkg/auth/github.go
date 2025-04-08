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
	"golang.org/x/oauth2/github"
)

// ===== GitHub OAuth =====

// GitHubUserInfo represents the user information returned by the GitHub API endpoint `/user`.
// See: https://docs.github.com/en/rest/users/users#get-the-authenticated-user
type GitHubUserInfo struct {
	ID        int    `json:"id"`         // The user's unique GitHub ID.
	Login     string `json:"login"`      // The user's GitHub username.
	Name      string `json:"name"`       // The user's display name (can be null).
	Email     string `json:"email"`      // The user's publicly visible email (can be null).
	AvatarURL string `json:"avatar_url"` // URL of the user's avatar.
}

// GitHubUserEmail represents an email address associated with a GitHub user,
// returned by the `/user/emails` endpoint.
// See: https://docs.github.com/en/rest/users/emails#list-email-addresses-for-the-authenticated-user
type GitHubUserEmail struct {
	Email      string `json:"email"`      // The email address.
	Primary    bool   `json:"primary"`    // Whether this is the user's primary email.
	Verified   bool   `json:"verified"`   // Whether GitHub has verified this email.
	Visibility string `json:"visibility"` // "public" or "private".
}

// fetchGitHubUserInfo retrieves the authenticated user's profile information from the GitHub API (`/user`).
// It requires an authorized http.Client.
func fetchGitHubUserInfo(ctx context.Context, client *http.Client) (*GitHubUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}
	req.Header.Add("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute user info request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var userInfo GitHubUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info response: %w", err)
	}
	return &userInfo, nil
}

// fetchGitHubUserEmails retrieves the authenticated user's email addresses from the GitHub API (`/user/emails`).
// It requires an authorized http.Client and the `user:email` scope.
func fetchGitHubUserEmails(ctx context.Context, client *http.Client) ([]GitHubUserEmail, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user emails request: %w", err)
	}
	req.Header.Add("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute user emails request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user emails: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var emails []GitHubUserEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return nil, fmt.Errorf("failed to decode user emails response: %w", err)
	}
	return emails, nil
}

// selectPrimaryGitHubEmail selects the best available email address from a list of GitHubUserEmail.
// It prioritizes the primary verified email, then the first verified email, then the first email overall.
func selectPrimaryGitHubEmail(emails []GitHubUserEmail) string {
	primaryEmail := ""
	firstVerified := ""
	firstEmail := ""
	for _, e := range emails {
		if e.Primary && e.Verified {
			primaryEmail = e.Email
			break
		}
		if e.Verified && firstVerified == "" {
			firstVerified = e.Email
		}
		if firstEmail == "" {
			firstEmail = e.Email
		}
	}
	if primaryEmail != "" {
		return primaryEmail
	} else if firstVerified != "" {
		return firstVerified
	}
	return firstEmail // Return the first email if no better option is found.
}

// gitHubLoginWithCode handles the final step of the GitHub OAuth flow.
// It exchanges the authorization code for an access token, fetches the user's profile
// information and email addresses from the GitHub API, and maps the data to the
// standardized User struct.
// Requires 'read:user' and 'user:email' scopes.
// Returns ErrFailedToExchangeCode or ErrFailedToGetUserInfo on failure.
func (o *OAuthHandler) gitHubLoginWithCode(ctx context.Context, code string) (*User, error) {
	logger := o.logEnricher(ctx, o.logger).Named("github_login")

	if o.githubOAuthConfig == nil {
		logger.Error("GitHub OAuth config not initialized")
		return nil, errors.New("github OAuth config not initialized")
	}

	// Exchange the code for an OAuth token
	token, err := o.githubOAuthConfig.Exchange(ctx, code)
	if err != nil {
		logger.Error("Failed to exchange code for token", zap.Error(err))
		return nil, ErrFailedToExchangeCode
	}

	if !token.Valid() {
		logger.Error("Received invalid token")
		return nil, errors.New("received invalid token from provider")
	}

	// Use the token to get an HTTP client
	client := o.githubOAuthConfig.Client(ctx, token)
	client.Timeout = 10 * time.Second // Set a timeout

	// Get the user info from GitHub's API
	githubUser, err := fetchGitHubUserInfo(ctx, client)
	if err != nil {
		logger.Error("Failed to get GitHub user info", zap.Error(err))
		return nil, ErrFailedToGetUserInfo
	}

	// If email is not public in the main user info, try fetching from /user/emails
	if githubUser.Email == "" {
		emails, emailErr := fetchGitHubUserEmails(ctx, client)
		if emailErr == nil && len(emails) > 0 {
			githubUser.Email = selectPrimaryGitHubEmail(emails)
		} else if emailErr != nil {
			// Log the error but don't fail the whole process if email fetch fails
			logger.Warn("Failed to fetch GitHub user emails", zap.Error(emailErr))
		}
	}

	// Create a standardized User from the GitHub user info
	username := githubUser.Name
	if username == "" { // Use login name if display name is not set
		username = githubUser.Login // Fallback to login name if display name is null.
	}

	// Create the standardized User struct.
	user := &User{
		Username:  username,
		Email:     githubUser.Email, // Email might be empty if none is public/verified or scope wasn't granted.
		AvatarUrl: githubUser.AvatarURL,
		// GitHub API v3 doesn't provide separate first/last names directly in /user.
	}

	logger.Info("GitHub login successful", zap.String("github_login", githubUser.Login), zap.String("email", user.Email))
	return user, nil
}

// GetGitHubAuthURL generates the URL to redirect the user to for GitHub authentication.
// It includes the client ID, redirect URL, requested scopes ('read:user', 'user:email'), and state.
func (o *OAuthHandler) GetGitHubAuthURL(ctx context.Context, state string) string {
	logger := o.logEnricher(ctx, o.logger).Named("github_auth_url")
	if o.githubOAuthConfig == nil {
		logger.Error("GitHub OAuth config not initialized for GetGitHubAuthURL")
		return ""
	}
	// Use AuthCodeURL to generate the URL
	// Scopes requested: "user:email" (primary email) and "read:user" (basic profile)
	return o.githubOAuthConfig.AuthCodeURL(state) // Scopes are already defined in the config.
}

// registerGitHubOAuth creates and stores the oauth2.Config for GitHub,
// using the credentials provided in the main OAuthConfig.
// It sets the 'read:user' and 'user:email' scopes.
func (o *OAuthHandler) registerGitHubOAuth(ctx context.Context) error {
	logger := o.logEnricher(ctx, o.logger).Named("register_github")
	if o.config.GitHubOAuthClientID == "" || o.config.GitHubOAuthClientSecret == "" {
		logger.Error("GitHub OAuth client ID or secret missing during registration")
		return errors.New("github OAuth client ID and secret are required")
	}

	o.githubOAuthConfig = &oauth2.Config{
		ClientID:     o.config.GitHubOAuthClientID,
		ClientSecret: o.config.GitHubOAuthClientSecret,
		RedirectURL:  o.config.GitHubOAuthRedirectURL,
		Scopes:       []string{"user:email", "read:user"}, // Request email and basic profile
		Endpoint:     github.Endpoint,                     // GitHub's OAuth2 endpoints
	}

	logger.Info("GitHub OAuth handler registered using golang.org/x/oauth2")
	return nil
}
