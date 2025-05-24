package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/linkedin"
)

// ===== LinkedIn OAuth =====

// LinkedInUserInfo represents the basic profile information returned by LinkedIn's Profile API (`/v2/me`).
// Requires `profile` or `r_liteprofile` scope. Structure based on common fields.
// See: https://learn.microsoft.com/en-us/linkedin/shared/integrations/people/profile-api
type LinkedInUserInfo struct {
	ID                 string           `json:"id"`                       // LinkedIn member ID.
	LocalizedFirstName string           `json:"localizedFirstName"`       // User's first name in preferred language.
	LocalizedLastName  string           `json:"localizedLastName"`        // User's last name in preferred language.
	ProfilePicture     *LinkedInPicture `json:"profilePicture,omitempty"` // Profile picture details (nested structure).
}

// LinkedInPicture represents the profile picture data structure returned by the Profile API.
// The actual image URL is often nested within 'elements' and 'identifiers'.
type LinkedInPicture struct {
	DisplayImage string                 `json:"displayImage"`       // Often a URN, e.g., "urn:li:digitalmediaAsset:..."
	Elements     []LinkedInImageElement `json:"elements,omitempty"` // Array containing image elements.
}

// LinkedInImageElement is part of the nested structure for profile pictures.
type LinkedInImageElement struct {
	Identifiers []LinkedInImageIdentifier `json:"identifiers"` // Contains identifiers with the actual URL.
}

// LinkedInImageIdentifier holds the image URL within the nested picture structure.
type LinkedInImageIdentifier struct {
	Identifier string `json:"identifier"` // The actual image URL.
}

// LinkedInEmailInfo represents the structure returned by LinkedIn's Email API (`/v2/emailAddress`).
// Requires `email` or `r_emailaddress` scope.
// See: https://learn.microsoft.com/en-us/linkedin/shared/integrations/people/email-address-api
type LinkedInEmailInfo struct {
	Elements []LinkedInEmailElement `json:"elements"` // Array containing email elements.
}

// LinkedInEmailElement contains details about a single email address associated with the user.
type LinkedInEmailElement struct {
	Handle      string `json:"handle"`  // URN representing the email, e.g., "urn:li:emailAddress:..."
	HandleTilde string `json:"handle~"` // Contains the actual email address.
	Type        string `json:"type"`    // Type, usually "EMAIL".
	Primary     bool   `json:"primary"` // Indicates if this is the primary email. (May not always be present/reliable).
}

// linkedinProvider implements the Provider interface for LinkedIn OAuth.
type linkedinProvider struct {
	handler *OAuthHandler
}

func (l *linkedinProvider) AuthURL(ctx context.Context, state string) string {
	return l.handler.GetLinkedInAuthURL(ctx, state)
}

func (l *linkedinProvider) Login(ctx context.Context, code string) (*User, error) {
	return l.handler.linkedInLoginWithCode(ctx, code)
}

// fetchLinkedInUserInfo retrieves the user's basic profile information from the LinkedIn API (`/v2/me`).
// It requires an authorized http.Client and appropriate scopes (`profile` or `r_liteprofile`).
// It requests specific fields using projections.
func fetchLinkedInUserInfo(ctx context.Context, client *http.Client) (*LinkedInUserInfo, error) {
	// Request specific fields: id, localizedFirstName, localizedLastName, and profilePicture with displayImage elements.
	// Example projection: profilePicture(displayImage~:playableStreams) - might need adjustment based on API version
	// Simpler projection for basic info:
	// reqURL := "https://api.linkedin.com/v2/me?projection=(id,localizedFirstName,localizedLastName)"
	// Projection including profile picture (may require specific permissions and structure parsing):
	reqURL := "https://api.linkedin.com/v2/me?projection=(id,localizedFirstName,localizedLastName,profilePicture(displayImage~:playableStreams))"

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

	var userInfo LinkedInUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		// Try reading the body again for debugging if JSON fails
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode user info response: %w. Body: %s", err, string(bodyBytes))
	}
	return &userInfo, nil
}

// fetchLinkedInEmail retrieves the user's email address(es) from the LinkedIn API (`/v2/emailAddress`).
// It requires an authorized http.Client and the `email` or `r_emailaddress` scope.
// It attempts to return the primary email address found in the 'handle~' field.
func fetchLinkedInEmail(ctx context.Context, client *http.Client) (string, error) {
	// Request the email address, projecting the 'handle~' field which contains the actual email.
	reqURL := "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))"
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create email request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute email request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get email: status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var emailInfo LinkedInEmailInfo
	if err := json.NewDecoder(resp.Body).Decode(&emailInfo); err != nil {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to decode email response: %w. Body: %s", err, string(bodyBytes))
	}

	// Find the primary email address
	for _, element := range emailInfo.Elements {
		if element.HandleTilde != "" { // Assuming HandleTilde contains the email
			// LinkedIn API might have changed, primary flag might not be reliable or present.
			// Often, the first email returned or the one in HandleTilde is the primary.
			return element.HandleTilde, nil
		}
	}

	return "", errors.New("no email address found in response")
}

// extractLinkedInProfilePictureURL attempts to extract a usable profile picture URL
// from the potentially complex LinkedInPicture structure.
// It prioritizes URLs found within the nested identifiers.
func extractLinkedInProfilePictureURL(pic *LinkedInPicture) string {
	if pic == nil {
		return ""
	}
	// Check nested elements first, as this is the common structure.
	if len(pic.Elements) > 0 {
		for _, elem := range pic.Elements {
			for _, id := range elem.Identifiers {
				if id.Identifier != "" {
					return id.Identifier // Return the first valid URL found.
				}
			}
		}
	}
	// Iterate through elements and identifiers to find the URL
	// This structure can be complex; adjust based on actual API response
	for _, elem := range pic.Elements {
		for _, id := range elem.Identifiers {
			if id.Identifier != "" {
				// Assuming the first identifier found is the desired image URL
				return id.Identifier
			}
		}
	}
	// Fallback or alternative parsing if the structure differs
	if pic.DisplayImage != "" && strings.Contains(pic.DisplayImage, "urn:li:digitalmediaAsset") {
		// This part is speculative and depends on the exact 'displayImage' format
		// It might contain a URN that needs further resolution or parsing.
		// For simplicity, we'll return empty if the direct URL isn't found in identifiers.
		return ""
	}

	return "" // Return empty if no URL found in identifiers or other checks.
}

// linkedInLoginWithCode handles the final step of the LinkedIn OAuth flow.
// It exchanges the authorization code for an access token, fetches the user's profile
// information and email address from the LinkedIn API, and maps the data to the
// standardized User struct.
// Requires appropriate scopes like 'profile', 'email', 'openid' (or older 'r_liteprofile', 'r_emailaddress').
// Returns ErrFailedToExchangeCode or ErrFailedToGetUserInfo on failure.
func (o *OAuthHandler) linkedInLoginWithCode(ctx context.Context, code string) (*User, error) {
	logger := o.logEnricher(ctx, o.logger).Named("linkedin_login")

	if o.linkedInOAuthConfig == nil {
		logger.Error("LinkedIn OAuth config not initialized")
		return nil, errors.New("linkedin OAuth config not initialized")
	}

	// Exchange the code for an OAuth token
	token, err := o.linkedInOAuthConfig.Exchange(ctx, code)
	if err != nil {
		logger.Error("Failed to exchange code for token", zap.Error(err))
		return nil, ErrFailedToExchangeCode
	}

	if !token.Valid() {
		logger.Error("Received invalid token")
		return nil, errors.New("received invalid token from provider")
	}

	// Use the token to get an HTTP client
	client := o.linkedInOAuthConfig.Client(ctx, token)
	client.Timeout = 15 * time.Second // Increased timeout for potentially slower LinkedIn APIs

	// Get the user info from LinkedIn's API
	linkedInUser, err := fetchLinkedInUserInfo(ctx, client)
	if err != nil {
		logger.Error("Failed to get LinkedIn user info", zap.Error(err))
		return nil, ErrFailedToGetUserInfo
	}

	// Get the user's primary email address (requires 'email' scope)
	email := ""
	// Check if email scope was requested before attempting to fetch
	hasEmailScope := false
	for _, scope := range o.linkedInOAuthConfig.Scopes {
		if scope == "email" || scope == "r_emailaddress" { // Check for common email scopes
			hasEmailScope = true
			break
		}
	}

	if hasEmailScope {
		email, err = fetchLinkedInEmail(ctx, client)
		if err != nil {
			// Log warning but don't fail the login if email fetch fails
			logger.Warn("Failed to get LinkedIn email", zap.Error(err))
		}
	} else {
		logger.Info("Email scope not requested for LinkedIn, skipping email fetch.")
	}

	// Extract profile picture URL
	avatarURL := extractLinkedInProfilePictureURL(linkedInUser.ProfilePicture)

	// Create a standardized User from the LinkedIn user info
	user := &User{
		// Use full name as username to maintain consistency with other providers
		Username:  linkedInUser.LocalizedFirstName + " " + linkedInUser.LocalizedLastName,
		Email:     email,
		AvatarUrl: avatarURL,
		FirstName: linkedInUser.LocalizedFirstName,
		LastName:  linkedInUser.LocalizedLastName,
	}

	logger.Info("LinkedIn login successful", zap.String("linkedin_id", linkedInUser.ID), zap.String("email", user.Email))
	return user, nil
}

// GetLinkedInAuthURL generates the URL to redirect the user to for LinkedIn authentication.
// It includes the client ID, redirect URL, requested scopes, and state.
func (o *OAuthHandler) GetLinkedInAuthURL(ctx context.Context, state string) string {
	logger := o.logEnricher(ctx, o.logger).Named("linkedin_auth_url")
	if o.linkedInOAuthConfig == nil {
		logger.Error("LinkedIn OAuth config not initialized for GetLinkedInAuthURL")
		return ""
	}
	// Use AuthCodeURL to generate the URL
	// Scopes are defined in the config
	return o.linkedInOAuthConfig.AuthCodeURL(state) // Scopes are defined in the config.
}

// registerLinkedInOAuth creates and stores the oauth2.Config for LinkedIn,
// using the credentials provided in the main OAuthConfig.
// It sets standard OpenID Connect scopes ('profile', 'email', 'openid').
// Note: Older LinkedIn apps might use 'r_liteprofile', 'r_emailaddress'. Adjust scopes if needed.
func (o *OAuthHandler) registerLinkedInOAuth(ctx context.Context) (Provider, error) {
	logger := o.logEnricher(ctx, o.logger).Named("register_linkedin")
	if o.config.LinkedInOAuthClientID == "" || o.config.LinkedInOAuthClientSecret == "" {
		logger.Error("LinkedIn OAuth client ID or secret missing during registration")
		return nil, errors.New("linkedin OAuth client ID and secret are required")
	}

	// Define required scopes. 'r_liteprofile' for basic profile, 'r_emailaddress' for email.
	// Note: LinkedIn scope names might change. Verify with current LinkedIn developer docs.
	// As of recent changes, 'profile', 'email', 'openid' are common OpenID Connect scopes.
	// If using older V2 APIs, 'r_liteprofile' and 'r_emailaddress' might be needed.
	// Let's assume newer OpenID Connect scopes for this example. Adjust if necessary.
	scopes := []string{"profile", "email", "openid"} // Or: []string{"r_liteprofile", "r_emailaddress"}

	o.linkedInOAuthConfig = &oauth2.Config{
		ClientID:     o.config.LinkedInOAuthClientID,
		ClientSecret: o.config.LinkedInOAuthClientSecret,
		RedirectURL:  o.config.LinkedInOAuthRedirectURL,
		Scopes:       scopes,
		Endpoint:     linkedin.Endpoint, // LinkedIn's OAuth2 endpoints
	}

	logger.Info("LinkedIn OAuth handler registered using golang.org/x/oauth2", zap.Strings("scopes", scopes))
	return &linkedinProvider{handler: o}, nil
}
