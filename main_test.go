package main_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/SvytDola/go-auth-jwt/internal"
	"github.com/SvytDola/go-auth-jwt/internal/dto/auth"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

func TestGetTokens(t *testing.T) {
	urlTemplate := "/auth/accessToken?user_id=%s"
	guid := "7cbb9a33-224e-4945-8f0c-712e995374f9"

	path := fmt.Sprintf(urlTemplate, guid)

	req, err := http.NewRequest("GET", path, nil)
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
		t.Fatal(jsonError)
	}

	accessToken, err := jwt.Parse(authGetTokenResponse.AccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	accessTokenClaims, ok := accessToken.Claims.(jwt.MapClaims)
	if !(ok && accessToken.Valid) {
		t.Error("Invalid access token.")
	}

	refreshToken, err := jwt.Parse(authGetTokenResponse.AccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	refreshTokenClaims, okR := refreshToken.Claims.(jwt.MapClaims)
	if !(okR && refreshToken.Valid) {
		t.Error("Invalid refresh token.")
	}

	i := refreshTokenClaims["refresh_id"]
	i2 := accessTokenClaims["refresh_id"]

	if i != i2 {
		t.Errorf("Difference refresh id between accessToken (%s) and refreshToken (%s).", i2, i)
	}

	var selected internal.RefreshTokenInfo
	hex, errParseHex := primitive.ObjectIDFromHex(i.(string))
	if errParseHex != nil {
		t.Error("Invalid refresh id")
	}
	errFindOne := app.RefreshTokenCollection.FindOne(context.TODO(), bson.D{{"_id", hex}}).Decode(&selected)

	if errFindOne != nil {
		t.Error(err)
	}

	log.Println(selected.RefreshToken)

}
