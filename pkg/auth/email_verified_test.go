package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"golang.org/x/oauth2"
)

// profileClient answers every token exchange (POST) with a bearer token, plus
// idToken when set, and every GET with the profile registered for its host and
// path, or 404 when none is.
func profileClient(idToken string, profiles map[string]string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"access_token":"test-token","token_type":"Bearer","expires_in":3600,"id_token":%q}`, idToken)), nil
		}
		if body, ok := profiles[r.URL.Host+r.URL.Path]; ok {
			return jsonResponse(http.StatusOK, body), nil
		}
		return jsonResponse(http.StatusNotFound, `{}`), nil
	})}
}

func appleIDToken(claims string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".sig"
}

func TestLoginEmailVerified(t *testing.T) {
	verified, unverified := true, false
	tests := []struct {
		name         string
		provider     OAuthProvider
		idToken      string
		profiles     map[string]string
		discordIDs   bool
		wantEmail    string
		wantVerified *bool
	}{
		{name: "google verified", provider: GoogleOAuthProvider,
			profiles:  map[string]string{"www.googleapis.com/oauth2/v2/userinfo": `{"email":"a@example.com","verified_email":true}`},
			wantEmail: "a@example.com", wantVerified: &verified},
		{name: "google unverified", provider: GoogleOAuthProvider,
			profiles:  map[string]string{"www.googleapis.com/oauth2/v2/userinfo": `{"email":"a@example.com","verified_email":false}`},
			wantEmail: "a@example.com", wantVerified: &unverified},
		{name: "google no email", provider: GoogleOAuthProvider,
			profiles: map[string]string{"www.googleapis.com/oauth2/v2/userinfo": `{"id":"1"}`}},
		{name: "github public email looked up", provider: GitHubOAuthProvider,
			profiles: map[string]string{
				"api.github.com/user":        `{"login":"a","email":"A@Example.com"}`,
				"api.github.com/user/emails": `[{"email":"b@example.com","primary":true,"verified":false},{"email":"a@example.com","verified":true}]`,
			},
			wantEmail: "A@Example.com", wantVerified: &verified},
		{name: "github private email selected", provider: GitHubOAuthProvider,
			profiles: map[string]string{
				"api.github.com/user":        `{"login":"a"}`,
				"api.github.com/user/emails": `[{"email":"b@example.com","primary":true,"verified":false}]`,
			},
			wantEmail: "b@example.com", wantVerified: &unverified},
		{name: "github emails unavailable", provider: GitHubOAuthProvider,
			profiles:  map[string]string{"api.github.com/user": `{"login":"a","email":"a@example.com"}`},
			wantEmail: "a@example.com"},
		{name: "discord verified", provider: DiscordOAuthProvider,
			profiles:  map[string]string{"discord.com/api/users/@me": `{"id":"42","email":"a@example.com","verified":true}`},
			wantEmail: "a@example.com", wantVerified: &verified},
		{name: "discord unverified", provider: DiscordOAuthProvider,
			profiles:  map[string]string{"discord.com/api/users/@me": `{"id":"42","email":"a@example.com","verified":false}`},
			wantEmail: "a@example.com", wantVerified: &unverified},
		{name: "discord id as email", provider: DiscordOAuthProvider, discordIDs: true,
			profiles:  map[string]string{"discord.com/api/users/@me": `{"id":"42","email":"a@example.com","verified":true}`},
			wantEmail: "42@discordid.com"},
		{name: "okta verified", provider: OktaOAuthProvider,
			profiles:  map[string]string{"example.okta.com/oauth2/v1/userinfo": `{"sub":"1","email":"a@example.com","email_verified":true}`},
			wantEmail: "a@example.com", wantVerified: &verified},
		{name: "okta unverified", provider: OktaOAuthProvider,
			profiles:  map[string]string{"example.okta.com/oauth2/v1/userinfo": `{"sub":"1","email":"a@example.com","email_verified":false}`},
			wantEmail: "a@example.com", wantVerified: &unverified},
		{name: "quran.foundation verified", provider: QuranFoundationOAuthProvider,
			profiles:  map[string]string{"auth.quran.foundation/userinfo": `{"sub":"1","email":"a@example.com","email_verified":true}`},
			wantEmail: "a@example.com", wantVerified: &verified},
		{name: "quran.foundation unverified", provider: QuranFoundationOAuthProvider,
			profiles:  map[string]string{"auth.quran.foundation/userinfo": `{"sub":"1","email":"a@example.com","email_verified":false}`},
			wantEmail: "a@example.com", wantVerified: &unverified},
		{name: "quran.foundation claim absent", provider: QuranFoundationOAuthProvider,
			profiles:  map[string]string{"auth.quran.foundation/userinfo": `{"sub":"1","email":"a@example.com"}`},
			wantEmail: "a@example.com"},
		{name: "facebook unavailable", provider: FacebookOAuthProvider,
			profiles:  map[string]string{"graph.facebook.com/me": `{"id":"1","email":"a@example.com"}`},
			wantEmail: "a@example.com"},
		{name: "linkedin unavailable", provider: LinkedInOAuthProvider,
			profiles: map[string]string{
				"api.linkedin.com/v2/me":           `{"id":"1"}`,
				"api.linkedin.com/v2/emailAddress": `{"elements":[{"handle~":"a@example.com"}]}`,
			},
			wantEmail: "a@example.com"},
		{name: "apple boolean claim", provider: AppleOAuthProvider,
			idToken:   appleIDToken(`{"sub":"1","email":"a@example.com","email_verified":true}`),
			wantEmail: "a@example.com", wantVerified: &verified},
		{name: "apple string claim", provider: AppleOAuthProvider,
			idToken:   appleIDToken(`{"sub":"1","email":"a@example.com","email_verified":"false"}`),
			wantEmail: "a@example.com", wantVerified: &unverified},
		{name: "apple claim absent", provider: AppleOAuthProvider,
			idToken:   appleIDToken(`{"sub":"1","email":"a@example.com"}`),
			wantEmail: "a@example.com"},
		{name: "apple no email", provider: AppleOAuthProvider,
			idToken: appleIDToken(`{"sub":"1","email_verified":"true"}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newRedirectTestHandler(t)
			h.config.UseDiscordIdAsEmail = tt.discordIDs
			client := profileClient(tt.idToken, tt.profiles)
			h.appleOauthHandler.HTTPClient = client
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
			user, err := h.LoginWithCode(ctx, tt.provider, "test-code", defaultRedirectURI)
			if err != nil {
				t.Fatalf("login: %v", err)
			}
			if user.Email != tt.wantEmail {
				t.Errorf("Email = %q, want %q", user.Email, tt.wantEmail)
			}
			switch {
			case tt.wantVerified == nil && user.EmailVerified != nil:
				t.Errorf("EmailVerified = %v, want nil", *user.EmailVerified)
			case tt.wantVerified != nil && user.EmailVerified == nil:
				t.Errorf("EmailVerified = nil, want %v", *tt.wantVerified)
			case tt.wantVerified != nil && *user.EmailVerified != *tt.wantVerified:
				t.Errorf("EmailVerified = %v, want %v", *user.EmailVerified, *tt.wantVerified)
			}
		})
	}
}

func TestUserEmailVerifiedJSON(t *testing.T) {
	unverified := false
	for _, tt := range []struct {
		verified *bool
		want     string
	}{
		{nil, `{"username":"","email":"","avatar_url":"","first_name":"","last_name":""}`},
		{&unverified, `{"username":"","email":"","avatar_url":"","first_name":"","last_name":"","email_verified":false}`},
	} {
		got, err := json.Marshal(User{EmailVerified: tt.verified})
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tt.want {
			t.Errorf("json = %s, want %s", got, tt.want)
		}
	}
}
