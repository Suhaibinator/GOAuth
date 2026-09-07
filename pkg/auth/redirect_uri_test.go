package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const defaultRedirectURI = "https://main.example/auth/oauth/callback"
const studentRedirectURI = "https://students.example/auth/oauth/callback?value=a%2Fb"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func newRedirectTestHandler(t *testing.T) *OAuthHandler {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	h := NewOAuthHandler(zap.NewNop(), func(_ context.Context, l *zap.Logger) *zap.Logger { return l }, &OAuthConfig{
		GoogleOAuthClientID: "google", GoogleOAuthClientSecret: "secret", GoogleOAuthRedirectURL: defaultRedirectURI,
		FacebookOAuthClientID: "facebook", FacebookOAuthClientSecret: "secret", FacebookOAuthRedirectURL: defaultRedirectURI,
		GitHubOAuthClientID: "github", GitHubOAuthClientSecret: "secret", GitHubOAuthRedirectURL: defaultRedirectURI,
		LinkedInOAuthClientID: "linkedin", LinkedInOAuthClientSecret: "secret", LinkedInOAuthRedirectURL: defaultRedirectURI,
		DiscordOAuthClientID: "discord", DiscordOAuthClientSecret: "secret", DiscordOAuthRedirectURL: defaultRedirectURI,
		QuranFoundationOAuthClientID: "quran", QuranFoundationOAuthClientSecret: "secret", QuranFoundationOAuthRedirectURL: defaultRedirectURI,
		OktaOAuthClientID: "okta", OktaOAuthClientSecret: "secret", OktaOAuthRedirectURL: defaultRedirectURI, OktaOAuthDomain: "example.okta.com",
		AppleOAuthClientID: "apple", AppleOAuthTeamID: "team", AppleOAuthKeyID: "key", AppleOAuthRedirectURL: defaultRedirectURI,
		AppleOAuthPrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
	})
	if len(h.providers) != 8 {
		t.Fatalf("registered %d providers, want 8", len(h.providers))
	}
	return h
}

// Exercise the public dispatch and each provider's actual token request. A token
// rejection deliberately ends these tests before unrelated user-info behavior.
func TestExchangeRedirectURIAllProviders(t *testing.T) {
	h := newRedirectTestHandler(t)
	for provider := GoogleOAuthProvider; provider <= OktaOAuthProvider; provider++ {
		t.Run(fmt.Sprint(provider), func(t *testing.T) {
			var requests int
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests++
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if got := r.PostForm.Get("redirect_uri"); got != studentRedirectURI {
					t.Errorf("redirect_uri = %q, want %q", got, studentRedirectURI)
				}
				if got := r.PostForm.Get("code"); got != "test-code" {
					t.Errorf("code = %q", got)
				}
				return jsonResponse(http.StatusBadRequest, `{"error":"invalid_grant"}`), nil
			})}
			h.appleOauthHandler.HTTPClient = client
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
			_, err := h.LoginWithCode(ctx, provider, "test-code", studentRedirectURI)
			if !errors.Is(err, ErrFailedToExchangeCode) {
				t.Fatalf("error = %v", err)
			}
			if requests == 0 {
				t.Fatal("no exchange request")
			}
		})
	}
	for _, config := range []*oauth2.Config{h.googleOAuthConfig, h.facebookOAuthConfig, h.githubOAuthConfig, h.linkedInOAuthConfig, h.discordOAuthConfig, h.quranFoundationOAuthConfig, h.oktaOAuthConfig} {
		if config.RedirectURL != defaultRedirectURI {
			t.Errorf("shared redirect changed to %q", config.RedirectURL)
		}
	}
	if h.appleOauthHandler.RedirectURL != defaultRedirectURI {
		t.Fatal("shared Apple redirect changed")
	}
}

func TestMissingRedirectURI(t *testing.T) {
	h := newRedirectTestHandler(t)
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("empty redirect must not make a request")
		return nil, errors.New("unexpected request")
	})}
	h.appleOauthHandler.HTTPClient = client
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	for provider, p := range h.providers {
		if _, err := h.LoginWithCode(ctx, provider, "code", ""); !errors.Is(err, ErrMissingRedirectURI) {
			t.Errorf("provider %v: %v", provider, err)
		}
		// Provider implementations are callable through the public interface too.
		if _, err := p.Login(ctx, "code", ""); !errors.Is(err, ErrMissingRedirectURI) {
			t.Errorf("direct provider %v: %v", provider, err)
		}
	}
	if _, err := h.appleOauthHandler.Exchange("code", ""); !errors.Is(err, ErrMissingRedirectURI) {
		t.Errorf("Apple Exchange: %v", err)
	}
	if _, err := h.LoginWithCode(ctx, OAuthProvider(-1), "code", studentRedirectURI); err == nil {
		t.Fatal("unknown provider accepted")
	}
	delete(h.providers, GoogleOAuthProvider)
	if _, err := h.LoginWithCode(ctx, GoogleOAuthProvider, "code", studentRedirectURI); err == nil {
		t.Fatal("unconfigured provider accepted")
	}
}

func TestGoogleConcurrentRedirectURIs(t *testing.T) {
	h := newRedirectTestHandler(t)
	const attempts = 32
	var tokens, profiles atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		redirectURI := defaultRedirectURI
		if i%2 == 1 {
			redirectURI = studentRedirectURI
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Host {
				case "oauth2.googleapis.com":
					tokens.Add(1)
					if err := r.ParseForm(); err != nil {
						return nil, err
					}
					if got := r.PostForm.Get("redirect_uri"); got != redirectURI {
						t.Errorf("exchange URI = %q, want %q", got, redirectURI)
					}
					return jsonResponse(http.StatusOK, `{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`), nil
				case "www.googleapis.com":
					profiles.Add(1)
					if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
						t.Errorf("authorization = %q", got)
					}
					return jsonResponse(http.StatusOK, `{"id":"123","name":"Test Student","email":"student@example.com","given_name":"Test","family_name":"Student"}`), nil
				default:
					return nil, fmt.Errorf("unexpected request %s", r.URL)
				}
			})}
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
			<-start
			user, err := h.LoginWithCode(ctx, GoogleOAuthProvider, "test-code", redirectURI)
			if err != nil {
				t.Errorf("login: %v", err)
				return
			}
			if user.Email != "student@example.com" || user.Username != "Test Student" {
				t.Errorf("unexpected user: %+v", user)
			}
		}()
	}
	close(start)
	wg.Wait()
	if tokens.Load() != attempts || profiles.Load() != attempts {
		t.Fatalf("tokens=%d profiles=%d, want %d each", tokens.Load(), profiles.Load(), attempts)
	}
	if h.googleOAuthConfig.RedirectURL != defaultRedirectURI {
		t.Fatal("shared redirect changed")
	}
	authURL, err := url.Parse(h.GetGoogleAuthURL(context.Background(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if got := authURL.Query().Get("redirect_uri"); got != defaultRedirectURI {
		t.Errorf("authorization default changed to %q", got)
	}
}
