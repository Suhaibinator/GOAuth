package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// ===== Sign in with Apple =====
// This implementation generates the required client secret JWT and exchanges
// the authorization code for tokens. ID token validation should still be
// performed by callers if needed.

// AppleOauthHandler handles OAuth operations for Sign in with Apple.
// It uses a JWT signed with your private key as the client secret.
type AppleOauthHandler struct {
	ClientID    string
	TeamID      string
	KeyID       string
	PrivateKey  *ecdsa.PrivateKey
	RedirectURL string
	HTTPClient  *http.Client
}

// appleProvider implements the Provider interface for Sign in with Apple.
type appleProvider struct {
	handler *OAuthHandler
}

func (a *appleProvider) AuthURL(ctx context.Context, state string) string {
	return a.handler.GetAppleAuthURL(ctx, state)
}

func (a *appleProvider) Login(ctx context.Context, code string) (*User, error) {
	return a.handler.appleLoginWithCode(ctx, code)
}

// generateClientSecret creates the JWT client secret required by Apple.
func (a *AppleOauthHandler) generateClientSecret() (string, error) {
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":"ES256","kid":"%s"}`, a.KeyID)))
	payload := fmt.Sprintf(`{"iss":"%s","iat":%d,"exp":%d,"aud":"https://appleid.apple.com","sub":"%s"}`,
		a.TeamID, now.Unix(), now.Add(5*time.Minute).Unix(), a.ClientID)
	payloadEnc := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := header + "." + payloadEnc
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, a.PrivateKey, h[:])
	if err != nil {
		return "", err
	}
	// Convert r,s to byte array as per JOSE encoding
	curveBits := a.PrivateKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	sig := make([]byte, keyBytes*2)
	r.FillBytes(sig[0:keyBytes])
	s.FillBytes(sig[keyBytes:])
	signature := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + signature, nil
}

// AppleTokenResponse represents the expected response from Apple's token endpoint `/auth/token`.
// See: https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse
type AppleTokenResponse struct {
	AccessToken  string `json:"access_token"`  // The access token for calling Apple APIs (rarely used directly).
	TokenType    string `json:"token_type"`    // Typically "Bearer".
	ExpiresIn    int    `json:"expires_in"`    // The expiry duration of the access token in seconds.
	RefreshToken string `json:"refresh_token"` // The refresh token (if requested and applicable).
	IDToken      string `json:"id_token"`      // A JWT containing user information claims. THIS MUST BE VERIFIED.
}

// AppleUserInfo represents the user information extracted *primarily* from the ID token.
// Apple does not provide a standard userinfo endpoint.
type AppleUserInfo struct {
	ID    string `json:"sub"`   // The unique user identifier (subject claim from ID token).
	Email string `json:"email"` // The user's email address (from ID token).
	Name  string `json:"name"`  // Placeholder for name; usually obtained from initial auth form post, not token.
}

// NewAppleOauthHandler creates a new AppleOauthHandler with the provided (simplified) configuration.
// WARNING: The clientSecret parameter is handled incorrectly here for Apple's flow.
// A proper implementation needs TeamID, KeyID, and PrivateKey.
// NewAppleOauthHandler creates a new AppleOauthHandler using the provided credentials.
// privateKeyPEM should contain the contents of your `.p8` key.
func NewAppleOauthHandler(clientID, teamID, keyID, privateKeyPEM, redirectURL string) (*AppleOauthHandler, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode apple private key pem")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid apple private key: %w", err)
	}
	return &AppleOauthHandler{
		ClientID:    clientID,
		TeamID:      teamID,
		KeyID:       keyID,
		PrivateKey:  key,
		RedirectURL: redirectURL,
		HTTPClient:  &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Exchange attempts to exchange an authorization code for tokens at Apple's token endpoint.
func (a *AppleOauthHandler) Exchange(code string) (*AppleTokenResponse, error) {
	clientSecret, err := a.generateClientSecret()
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", a.ClientID)
	data.Set("client_secret", clientSecret)
	data.Set("redirect_uri", a.RedirectURL)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequest("POST", "https://appleid.apple.com/auth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to exchange code: %s, status: %d", string(body), resp.StatusCode)
	}

	var tokenResp AppleTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// GetUserInfo attempts to extract user information by decoding the ID token's payload.
// WARNING: This function performs NO VALIDATION of the ID token signature or claims.
// It is INSECURE and MUST be replaced with proper JWT validation using Apple's public keys
// and libraries like github.com/golang-jwt/jwt.
func (a *AppleOauthHandler) GetUserInfo(token *AppleTokenResponse) (*AppleUserInfo, error) {
	if token == nil || token.IDToken == "" {
		return nil, errors.New("cannot get user info from nil or empty token")
	}

	parts := strings.Split(token.IDToken, ".")
	if len(parts) < 2 { // A JWT has 3 parts, but we only need the payload (part 2) for insecure decoding.
		return nil, fmt.Errorf("invalid ID token format")
	}

	// Decode the payload (second part of the JWT)
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ID token payload: %w", err)
	}

	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		// Name might be nested or absent depending on scope and first login
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ID token claims: %w", err)
	}

	// Placeholder for name - Apple might send user info separately in the initial auth response
	// or within the ID token if requested and available.
	userInfo := &AppleUserInfo{
		ID:    claims.Sub,
		Email: claims.Email,
		Name:  "Apple User", // Default or retrieve if available
	}

	return userInfo, nil
}

// base64URLDecode is a helper function to decode Base64 URL encoded strings,
// handling padding and character replacements.
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if necessary.
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	// Replace URL-specific characters
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	return base64.StdEncoding.DecodeString(s)
}

// GetAuthURL generates the authorization URL for Sign in with Apple.
// It includes client ID, redirect URL, requested scopes (name, email), state,
// and sets response_type and response_mode.
// Note: Requesting 'name' scope might only yield results on the user's first sign-in.
func (a *AppleOauthHandler) GetAuthURL(state string) string {
	u, _ := url.Parse("https://appleid.apple.com/auth/authorize")
	q := u.Query()
	q.Set("client_id", a.ClientID)
	q.Set("redirect_uri", a.RedirectURL)
	// Requesting 'code id_token' might be more common if frontend handles ID token directly.
	q.Set("response_type", "code")
	q.Set("scope", "name email")        // Request name and email scopes.
	q.Set("response_mode", "form_post") // Apple recommends form_post.
	q.Set("state", state)
	// Consider adding 'nonce' parameter for replay protection.
	u.RawQuery = q.Encode()
	return u.String()
}

// appleLoginWithCode handles the simplified Apple login flow using an authorization code.
// WARNING: This function relies on the insecure Exchange and GetUserInfo methods of the
// current AppleOauthHandler. It does not perform proper client secret generation or ID token validation.
// It's suitable only for basic demonstration and MUST be heavily modified for production.
func (o *OAuthHandler) appleLoginWithCode(ctx context.Context, code string) (*User, error) {
	logger := o.logEnricher(ctx, o.logger).Named("apple_login")
	if o.appleOauthHandler == nil {
		logger.Error("Apple OAuth handler not initialized")
		return nil, errors.New("apple OAuth handler not initialized")
	}

	// Exchange the code for an access token and ID token
	token, err := o.appleOauthHandler.Exchange(code)
	if err != nil {
		o.logEnricher(ctx, o.logger).Error("Failed to exchange code for token", zap.Error(err))
		return nil, ErrFailedToExchangeCode
	}

	// Get the user info from the ID token
	appleUser, err := o.appleOauthHandler.GetUserInfo(token)
	if err != nil {
		o.logEnricher(ctx, o.logger).Error("Failed to get user info from ID token", zap.Error(err))
		return nil, ErrFailedToGetUserInfo
	}

	// Create a service user from the Apple user info
	user := &User{
		Username:  appleUser.Name, // Name might be missing after first login
		Email:     appleUser.Email,
		AvatarUrl: "", // Apple doesn't provide an avatar URL
	}

	return user, nil
}

// GetAppleAuthURL generates the authorization URL using the configured Apple handler.
func (o *OAuthHandler) GetAppleAuthURL(ctx context.Context, state string) string {
	logger := o.logEnricher(ctx, o.logger).Named("apple_auth_url")
	if o.appleOauthHandler == nil {
		logger.Error("Apple OAuth handler not initialized for GetAppleAuthURL")
		return ""
	}
	// Note: Consider adding nonce support here if needed.
	return o.appleOauthHandler.GetAuthURL(state)
}

// registerAppleOAuth initializes the Apple OAuth handler using the configuration values.
func (o *OAuthHandler) registerAppleOAuth(ctx context.Context) (Provider, error) {
	logger := o.logEnricher(ctx, o.logger).Named("register_apple")
	if o.config.AppleOAuthClientID == "" || o.config.AppleOAuthTeamID == "" ||
		o.config.AppleOAuthKeyID == "" || o.config.AppleOAuthPrivateKey == "" {
		logger.Error("Apple OAuth configuration incomplete")
		return nil, errors.New("apple OAuth requires client id, team id, key id and private key")
	}

	handler, err := NewAppleOauthHandler(
		o.config.AppleOAuthClientID,
		o.config.AppleOAuthTeamID,
		o.config.AppleOAuthKeyID,
		o.config.AppleOAuthPrivateKey,
		o.config.AppleOAuthRedirectURL,
	)
	if err != nil {
		logger.Error("failed to create apple handler", zap.Error(err))
		return err
	}
	o.appleOauthHandler = handler
	logger.Info("Apple OAuth handler registered")
	return &appleProvider{handler: o}, nil
}

// Refresh exchanges a refresh token for a new access token using Apple's token endpoint.
func (a *AppleOauthHandler) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if refreshToken == "" {
		return nil, errors.New("refresh token is empty")
	}

	clientSecret, err := a.generateClientSecret()
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("client_id", a.ClientID)
	data.Set("client_secret", clientSecret)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://appleid.apple.com/auth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to refresh token: %s, status: %d", string(body), resp.StatusCode)
	}

	var tokenResp AppleTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}, nil
}
