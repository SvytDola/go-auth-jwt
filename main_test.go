package main_test

import (
	"encoding/json"
	"fmt"
	"github.com/SvytDola/go-auth-jwt/internal"
	"github.com/SvytDola/go-auth-jwt/internal/dto/auth"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

var app internal.App

func TestMain(m *testing.M) {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}
	jwtSecret := []byte(os.Getenv(""))
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
	urlTemplate := "/auth/token?user_id=%s"
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

}
