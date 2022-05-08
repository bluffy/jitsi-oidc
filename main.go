package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/joho/godotenv"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	JITSI_SECRET = goDotEnvVariable("JITSI_SECRET")
	JITSI_URL    = goDotEnvVariable("JITSI_URL")
	JITSI_SUB    = goDotEnvVariable("JITSI_SUB")

	ISSUER_BASE_URL = goDotEnvVariable("ISSUER_BASE_URL")
	BASE_URL        = goDotEnvVariable("BASE_URL")
	CLIENT_ID       = goDotEnvVariable("CLIENT_ID")
	SECRET          = goDotEnvVariable("SECRET")
)

func init() {
	// load .env file
	if _, err := os.Stat(".env"); err == nil {
		err := godotenv.Load(".env")

		if err != nil {
			log.Fatalf("Error loading .env file")
		}
	}
}

func goDotEnvVariable(key string) string {

	return os.Getenv(key)
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

var ctx context.Context
var provider *oidc.Provider
var config oauth2.Config

func handleStart(w http.ResponseWriter, r *http.Request) {

	state, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	setCallbackCookie(w, r, "state", state)
	setCallbackCookie(w, r, "nonce", nonce)

	http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {

	log.Println("TEST " + CLIENT_ID)

	state, err := r.Cookie("state")
	if err != nil {
		http.Error(w, "state not found", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != state.Value {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

	//w.Write([]byte(r.URL.RawQuery))

	oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	oidcConfig := &oidc.Config{
		ClientID: CLIENT_ID,
	}
	verifier := provider.Verifier(oidcConfig)

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	nonce, err := r.Cookie("nonce")
	if err != nil {
		http.Error(w, "nonce not found", http.StatusBadRequest)
		return
	}
	if idToken.Nonce != nonce.Value {
		http.Error(w, "nonce did not match", http.StatusBadRequest)
		return
	}

	oauth2Token.AccessToken = "*REDACTED*"

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)

}

func main() {
	ctx = context.Background()
	var err error
	provider, err = oidc.NewProvider(ctx, ISSUER_BASE_URL)
	if err != nil {
		log.Fatal(err)
	}

	redir := strings.Trim(BASE_URL, "/") + "/callback"

	config = oauth2.Config{
		ClientID:     CLIENT_ID,
		ClientSecret: SECRET,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redir,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	http.HandleFunc("/", handleStart)

	http.HandleFunc("/callback", handleCallback)

	log.Printf("listening on http://%s/", "0.0.0.0:3001")
	log.Fatal(http.ListenAndServe(":3001", nil))
}
