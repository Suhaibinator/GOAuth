package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Suhaibinator/GOAuth/pkg/auth" // Adjust import path if needed
	"github.com/google/uuid"                  // For generating state
	"go.uber.org/zap"
)

var (
	oauthHandler *auth.OAuthHandler
	logger       *zap.Logger
)

// --- Configuration (Replace with your actual credentials or load from env/config file) ---
const (
	googleClientID     = "YOUR_GOOGLE_CLIENT_ID"
	googleClientSecret = "YOUR_GOOGLE_CLIENT_SECRET"
	githubClientID     = "YOUR_GITHUB_CLIENT_ID"
	githubClientSecret = "YOUR_GITHUB_CLIENT_SECRET"
	// Add other provider credentials as needed
	redirectURIBase = "http://localhost:8080/callback/" // Base URL for callbacks
	traceIDKey      = "X-Request-ID"                    // Example context key for trace ID (used for header)
)

// Custom type for context keys to avoid collisions
type contextKey string

const (
	// Use a custom type for the context key to avoid collisions.
	// The original traceIDKey (string) is still used for the HTTP header.
	traceIDContextKey = contextKey(traceIDKey)
)

// -------------------------------------------------------------------------------------

func main() {
	var err error
	// Initialize logger
	logger, err = zap.NewDevelopment() // Use NewProduction in production
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() // Flushes buffer, if any

	// --- Initialize OAuth Handler ---
	oauthConfig := &auth.OAuthConfig{
		GoogleOAuthClientID:     googleClientID,
		GoogleOAuthClientSecret: googleClientSecret,
		GoogleOAuthRedirectURL:  redirectURIBase + "google",

		GitHubOAuthClientID:     githubClientID,
		GitHubOAuthClientSecret: githubClientSecret,
		GitHubOAuthRedirectURL:  redirectURIBase + "github",

		// Add configurations for other providers (Facebook, Discord, LinkedIn, Apple) here
		// Ensure Redirect URLs match the callback handlers below

		TraceIdKey: traceIDKey,
	}

	oauthHandler = auth.NewOAuthHandler(logger.Named("GOAuth"), func(ctx context.Context, logger *zap.Logger) *zap.Logger {
		return logger
	}, oauthConfig)
	if oauthHandler == nil {
		logger.Fatal("Failed to create OAuth handler")
	}

	// -----------------------------

	// --- Setup HTTP Server ---
	mux := http.NewServeMux()

	// Simple landing page
	mux.HandleFunc("/", handleHome)

	// Login initiation routes
	mux.HandleFunc("/login/google", handleLoginGoogle)
	mux.HandleFunc("/login/github", handleLoginGithub)
	// Add login routes for other providers...

	// Callback handling routes
	mux.HandleFunc("/callback/google", handleCallbackGoogle)
	mux.HandleFunc("/callback/github", handleCallbackGithub)
	// Add callback routes for other providers...

	// Middleware for logging and trace ID (basic example)
	loggedMux := loggingMiddleware(traceIDMiddleware(mux))

	server := &http.Server{
		Addr:         ":8080",
		Handler:      loggedMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	logger.Info("Starting simple OAuth example server on :8080")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("Server failed to start", zap.Error(err))
	}
	// ------------------------
}

// --- Handlers ---

func handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintln(w, `<h1>GOAuth Example</h1>`)
	fmt.Fprintln(w, `<p><a href="/login/google">Login with Google</a></p>`)
	fmt.Fprintln(w, `<p><a href="/login/github">Login with GitHub</a></p>`)
	// Add links for other providers
}

// handleLoginGoogle initiates the Google OAuth flow.
func handleLoginGoogle(w http.ResponseWriter, r *http.Request) {
	state := uuid.NewString() // Generate a unique state for CSRF protection
	// TODO: Store state securely (e.g., in session or short-lived DB entry) to verify later
	authURL := oauthHandler.GetGoogleAuthURL(r.Context(), state)
	if authURL == "" {
		http.Error(w, "Google Auth URL generation failed", http.StatusInternalServerError)
		return
	}
	logger.Info("Redirecting to Google for login", zap.String("state", state))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleLoginGithub initiates the GitHub OAuth flow.
func handleLoginGithub(w http.ResponseWriter, r *http.Request) {
	state := uuid.NewString()
	// TODO: Store state securely
	authURL := oauthHandler.GetGitHubAuthURL(r.Context(), state)
	if authURL == "" {
		http.Error(w, "GitHub Auth URL generation failed", http.StatusInternalServerError)
		return
	}
	logger.Info("Redirecting to GitHub for login", zap.String("state", state))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallbackGoogle handles the redirect back from Google.
func handleCallbackGoogle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errStr := r.URL.Query().Get("error")

	// TODO: Verify the received state against the stored state

	if errStr != "" {
		logger.Error("Google OAuth callback error", zap.String("error", errStr))
		http.Error(w, "Login failed: "+errStr, http.StatusUnauthorized)
		return
	}

	if code == "" {
		logger.Error("Google OAuth callback missing code")
		http.Error(w, "Login failed: Missing authorization code", http.StatusBadRequest)
		return
	}

	logger.Info("Received Google callback", zap.String("state", state), zap.String("code", code))

	user, err := oauthHandler.LoginWithCode(ctx, auth.GoogleOAuthProvider, code)
	if err != nil {
		logger.Error("Google login failed", zap.Error(err))
		http.Error(w, "Login failed processing code", http.StatusInternalServerError)
		return
	}

	// --- Login Successful ---
	logger.Info("Google Login Successful", zap.Any("user", user))
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Login Successful (Google)</h1><pre>%+v</pre>", user)
	// TODO: In a real app, create a session, set cookies, redirect to profile page, etc.
}

// handleCallbackGithub handles the redirect back from GitHub.
func handleCallbackGithub(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errStr := r.URL.Query().Get("error")

	// TODO: Verify state

	if errStr != "" {
		logger.Error("GitHub OAuth callback error", zap.String("error", errStr))
		http.Error(w, "Login failed: "+errStr, http.StatusUnauthorized)
		return
	}

	if code == "" {
		logger.Error("GitHub OAuth callback missing code")
		http.Error(w, "Login failed: Missing authorization code", http.StatusBadRequest)
		return
	}

	logger.Info("Received GitHub callback", zap.String("state", state), zap.String("code", code))

	user, err := oauthHandler.LoginWithCode(ctx, auth.GitHubOAuthProvider, code)
	if err != nil {
		logger.Error("GitHub login failed", zap.Error(err))
		http.Error(w, "Login failed processing code", http.StatusInternalServerError)
		return
	}

	// --- Login Successful ---
	logger.Info("GitHub Login Successful", zap.Any("user", user))
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Login Successful (GitHub)</h1><pre>%+v</pre>", user)
	// TODO: Real session management
}

// --- Middleware ---

// traceIDMiddleware adds a unique trace ID to the request context.
func traceIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID := r.Header.Get(traceIDKey)
		if traceID == "" {
			traceID = uuid.NewString()
		}
		// Add traceID to context using the custom key type
		ctx := context.WithValue(r.Context(), traceIDContextKey, traceID)
		// Set traceID in response header (using the original string key)
		w.Header().Set(traceIDKey, traceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// loggingMiddleware logs request details.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Use a response writer wrapper if you need to capture status code
		next.ServeHTTP(w, r)
		logger.Info("HTTP Request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
			zap.Duration("duration", time.Since(start)),
			// Retrieve traceID from context using the custom key type
			zap.String("trace_id", r.Context().Value(traceIDContextKey).(string)), // Assumes traceIDMiddleware runs first
		)
	})
}
