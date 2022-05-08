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
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
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

type PlayLoad struct {
	ID    string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func init() {
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

func main() {

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, ISSUER_BASE_URL)
	if err != nil {
		log.Fatal(err)
	}
	config := oauth2.Config{
		ClientID:     CLIENT_ID,
		ClientSecret: SECRET,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  strings.Trim(BASE_URL, "/") + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	r := gin.Default()

	r.GET("/room/:room", func(c *gin.Context) {

		room := c.Param("room")

		state, err := randString(16)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		nonce, err := randString(16)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.SetCookie("state", state, int(time.Hour.Seconds()), "/", "", c.Request.TLS != nil, true)
		c.SetCookie("nonce", nonce, int(time.Hour.Seconds()), "/", "", c.Request.TLS != nil, true)
		c.SetCookie("room", room, int(time.Hour.Seconds()), "/", "", c.Request.TLS != nil, true)
		c.Redirect(http.StatusFound, config.AuthCodeURL(state, oidc.Nonce(nonce)))
	})

	r.GET("/callback", func(c *gin.Context) {

		log.Println("TEST " + CLIENT_ID)

		state, err := c.Cookie("state")
		if err != nil {
			c.String(http.StatusInternalServerError, "state not found")
			return
		}
		if c.Query("state") != state {
			c.String(http.StatusInternalServerError, "state did not match")
			return
		}
		c.SetCookie("state", "", -1, "/", "", c.Request.TLS != nil, true)

		room, err := c.Cookie("room")
		if err != nil {
			c.String(http.StatusInternalServerError, "state not set")
			return
		}
		c.SetCookie("room", "", -1, "/", "", c.Request.TLS != nil, true)

		//w.Write([]byte(r.URL.RawQuery))

		oauth2Token, err := config.Exchange(ctx, c.Query("code"))
		if err != nil {
			c.String(http.StatusInternalServerError, "Failed to exchange token: "+err.Error())
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			c.String(http.StatusInternalServerError, "No id_token field in oauth2 token.")
			return
		}

		oidcConfig := &oidc.Config{
			ClientID: CLIENT_ID,
		}
		verifier := provider.Verifier(oidcConfig)

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			c.String(http.StatusInternalServerError, "Failed to verify ID Token: "+err.Error())

			return
		}

		nonce, err := c.Cookie("nonce")
		if err != nil {
			c.String(http.StatusInternalServerError, "nonce not found")

			return
		}
		if idToken.Nonce != nonce {
			c.String(http.StatusBadRequest, "nonce did not match")
			return
		}
		c.SetCookie("nonce", "", -1, "/", "", c.Request.TLS != nil, true)

		oauth2Token.AccessToken = "*REDACTED*"

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}

		/*
			data, err := json.MarshalIndent(resp, "", "    ")
			if err != nil {
				c.String(http.StatusInternalServerError, err.Error())
				return
			}
		*/

		var playLoad PlayLoad
		err = json.Unmarshal(*resp.IDTokenClaims, &playLoad)
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}

		claims := jwt.MapClaims{}
		claims["exp"] = time.Now().Add(time.Hour * 24 * 30).Unix()
		claims["aud"] = "jitsi"
		claims["sub"] = JITSI_SUB
		claims["iss"] = "jitsi"
		claims["room"] = room
		claims["context"] = `{
			"user": {
				"name": ` + playLoad.Name + `,
				"email": ` + playLoad.Email + `,
				"id": ` + playLoad.ID + `
			}
		}`

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, err := token.SignedString([]byte(JITSI_SECRET))
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
		}

		c.Redirect(http.StatusFound, JITSI_URL+"/room/"+room+"?jwt="+tokenString)

		/*

			data, err := json.MarshalIndent(resp, "", "    ")
			if err != nil {
				c.String(http.StatusInternalServerError, err.Error())
				return
			}
		*/

		/*


			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			jwt := model.Token{}

			jwt.AccessToken, err = token.SignedString([]byte(os.Getenv("TOKEN_SECRET_KEY")))
			if err != nil {
				return jwt, err
			}

			c.Redirect(http.StatusFound, JITSI_URL+"/room/"+room)

			//c.String(http.StatusOK, "OK")
		*/
		//c.JSON(http.StatusOK, resp)
	})

	r.Run(":3001") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
	/*
		http.HandleFunc("/", handleStart)

		http.HandleFunc("/callback", handleCallback)

		log.Printf("listening on http://%s/", "0.0.0.0:3001")
		log.Fatal(http.ListenAndServe(":3001", nil))
	*/
}
