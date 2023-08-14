package main_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/SvytDola/go-auth-jwt/internal"
	"github.com/SvytDola/go-auth-jwt/internal/dto/auth"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

var app internal.App
var jwtSecret []byte

func TestMain(m *testing.M) {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}
	jwtSecret = []byte(os.Getenv("JWT_KEY"))
	mongoDbUrl := os.Getenv("MONGODB_URI")
	mongoDbDatabase := os.Getenv("MONGODB_DB_NAME")

	app = internal.CreateApp(
		jwtSecret,
		time.Hour*24,
		time.Hour*24*7,
		mongoDbUrl,
		mongoDbDatabase,
	)
	code := m.Run()

	os.Exit(code)
}

func TestCrudAuthJwt(t *testing.T) {
	tokens := getTokensTestCase(t)
	refreshTokenTestCase(t, tokens)
}

func getTokensTestCase(t *testing.T) auth.GetTokensResponse {
	urlTemplate := "/auth/token?user_id=%s"
	guid := "7cbb9a33-224e-4945-8f0c-712e995374f9"

	urlPath := fmt.Sprintf(urlTemplate, guid)

	req, err := http.NewRequest("GET", urlPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	handler := http.HandlerFunc(app.GetTokensHandler)

	handler.ServeHTTP(response, req)

	if status := response.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expectedContentType := "application/json; charset=utf-8"
	if contentType := response.Header().Get("Content-Type"); contentType != expectedContentType {
		t.Errorf("handler returned wrong content type: got %v want %v", contentType, expectedContentType)
	}

	var authGetTokenResponse auth.GetTokensResponse

	jsonError := json.Unmarshal(response.Body.Bytes(), &authGetTokenResponse)

	if jsonError != nil {
		t.Fatal(response.Body.String())
	}

	checkTokens(t, authGetTokenResponse.AccessToken, authGetTokenResponse.RefreshToken)

	return authGetTokenResponse
}

func refreshTokenTestCase(t *testing.T, tokens auth.GetTokensResponse) {
	urlTemplate := "/auth/refresh-token?refresh_token=%s&access_token=%s"
	urlPath := fmt.Sprintf(urlTemplate, tokens.RefreshToken, tokens.AccessToken)

	req, err := http.NewRequest("GET", urlPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	handler := http.HandlerFunc(app.RefreshTokenHandler)

	handler.ServeHTTP(response, req)

	if status := response.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expectedContentType := "application/json; charset=utf-8"
	if contentType := response.Header().Get("Content-Type"); contentType != expectedContentType {
		t.Errorf("handler returned wrong content type: got %v want %v", contentType, expectedContentType)
	}

	var refreshTokenResponse auth.RefreshTokenResponse

	jsonError := json.Unmarshal(response.Body.Bytes(), &refreshTokenResponse)

	if jsonError != nil {
		t.Fatal(jsonError)
	}

	checkTokens(t, refreshTokenResponse.AccessToken, tokens.RefreshToken)
}

func checkTokens(t *testing.T, authAccessToken string, authRefreshToken string) {
	accessToken, err := jwt.Parse(authAccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	accessTokenClaims, ok := accessToken.Claims.(jwt.MapClaims)
	if !(ok && accessToken.Valid) {
		t.Error("Invalid access token.")
	}

	refreshToken, err := jwt.Parse(authRefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	refreshTokenClaims, okR := refreshToken.Claims.(jwt.MapClaims)
	if !(okR && refreshToken.Valid) {
		t.Error("Invalid refresh token.")
	}

	refreshIdFromRefreshToken := refreshTokenClaims["refresh_id"]
	refreshIdFromAccessToken := accessTokenClaims["refresh_id"]

	if refreshIdFromRefreshToken != refreshIdFromAccessToken {
		t.Errorf("Difference refresh id between accessToken (%s) and refreshToken (%s).", refreshIdFromAccessToken, refreshIdFromRefreshToken)
	}

	var selected internal.RefreshTokenInfo
	idFromHex, errParseHex := primitive.ObjectIDFromHex(refreshIdFromRefreshToken.(string))
	if errParseHex != nil {
		t.Error("Invalid refresh id")
	}
	errFindOne := app.RefreshTokenCollection.
		FindOne(context.TODO(), bson.D{{"_id", idFromHex}}).
		Decode(&selected)

	if errFindOne != nil {
		t.Error(err)
	}

	decodeString, err := hex.DecodeString(selected.RefreshToken)
	if err != nil {
		t.Error(err)
	}

	compareError := bcrypt.CompareHashAndPassword(decodeString, []byte(authRefreshToken))
	if compareError != nil {
		t.Error(compareError)
	}
}
