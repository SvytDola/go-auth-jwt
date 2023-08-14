package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/SvytDola/go-auth-jwt/service/dto/auth"
	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

type App struct {
	jwtSecret              []byte
	accessTokenExpiration  time.Duration
	refreshTokenExpiration time.Duration
	RefreshTokenCollection *mongo.Collection
}

type RefreshTokenInfo struct {
	Id           primitive.ObjectID `bson:"_id"`
	RefreshToken string             `bson:"refresh_token"`
}

func CreateApp(
	jwtSecret []byte,
	accessTokenExpiration time.Duration,
	refreshTokenExpiration time.Duration,
	mongoDbUrl string,
	database string,
) App {
	client, connectToDbError := mongo.Connect(
		context.TODO(),
		options.Client().ApplyURI(mongoDbUrl),
	)
	if connectToDbError != nil {
		log.Fatalln(connectToDbError)
	}

	db := client.Database(database)

	collection := db.Collection("refresh")
	return App{
		jwtSecret:              jwtSecret,
		accessTokenExpiration:  accessTokenExpiration,
		refreshTokenExpiration: refreshTokenExpiration,
		RefreshTokenCollection: collection,
	}
}

func (app *App) GetTokensHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		http.Error(w, "Request method not found.", http.StatusBadRequest)
		return
	}

	// Get user refreshId from request.
	userId := r.URL.Query().Get("user_id")

	if userId == "" {
		http.Error(w, "User id not sending.", http.StatusBadRequest)
		return
	}

	// Generate random refresh refreshId.
	refreshId := primitive.NewObjectID()
	text, marshalIdError := refreshId.MarshalText()
	refreshIdString := string(text)
	if marshalIdError != nil {
		http.Error(w, "Failed to marshal text", http.StatusInternalServerError)
		return
	}

	// Generate access token.
	token, accessTokenGenerationError := app.generateAccessToken(userId, refreshIdString)
	if accessTokenGenerationError != nil {
		http.Error(w, "Failed to generate Access token.", http.StatusInternalServerError)
		return
	}

	// Generate refresh token.
	refreshToken, refreshTokenGenerationError := app.generateRefreshToken(refreshIdString)
	if refreshTokenGenerationError != nil {
		http.Error(w, "Failed to generate hash from refresh token.", http.StatusInternalServerError)
		return
	}

	// Get hash from refresh token.
	bytes := []byte(refreshToken)
	hashedRefreshToken, refreshTokenGenerationError := bcrypt.GenerateFromPassword(bytes, 10)
	if refreshTokenGenerationError != nil {
		http.Error(w, "Failed to generate Refresh token.", http.StatusInternalServerError)
		return
	}

	// Save hashed refresh token in database.
	info := RefreshTokenInfo{RefreshToken: hex.EncodeToString(hashedRefreshToken), Id: refreshId}
	inserted, err := app.RefreshTokenCollection.InsertOne(context.TODO(), info)
	if err != nil {
		http.Error(w, "Failed to insert refresh token in db.", http.StatusInternalServerError)
		return
	}
	log.Printf("Inserted document with id %v\n", inserted.InsertedID)

	// Отправка Access и Refresh токенов клиенту
	resp := auth.GetTokensResponse{AccessToken: token, RefreshToken: refreshToken}
	jsonByteArray, jsonError := json.Marshal(resp)

	if jsonError != nil {
		http.Error(w, "Failed to convert json", http.StatusInternalServerError)
		return
	}

	_, writeBodyError := w.Write(jsonByteArray)
	if writeBodyError != nil {
		http.Error(w, "Failed to write in body", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

}

func (app *App) generateJwtToken(claims jwt.MapClaims, expiration time.Duration) (string, error) {
	claims["exp"] = time.Now().Add(expiration).Unix()
	return jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(app.jwtSecret)
}

func (app *App) generateAccessToken(userId string, refreshTokenId string) (string, error) {
	accessTokenClaims := jwt.MapClaims{
		"refresh_id": refreshTokenId,
		"user_id":    userId,
	}
	return app.generateJwtToken(accessTokenClaims, app.accessTokenExpiration)
}

func (app *App) generateRefreshToken(refreshTokenId string) (string, error) {
	refreshTokenClaims := jwt.MapClaims{
		"refresh_id": refreshTokenId,
	}
	return app.generateJwtToken(refreshTokenClaims, app.refreshTokenExpiration)
}

func (app *App) Run(addr string, handler http.Handler) error {
	http.HandleFunc("/auth/token", app.GetTokensHandler)
	http.HandleFunc("/auth/refresh-token", app.RefreshTokenHandler)

	return http.ListenAndServe(addr, handler)
}

func (app *App) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Check method
	if r.Method != "GET" {
		http.Error(w, "Request method not found.", http.StatusBadRequest)
		return
	}

	// Get refresh token from request.
	refreshToken := r.URL.Query().Get("refresh_token")
	if refreshToken == "" {
		http.Error(w, "Refresh token not sending.", http.StatusBadRequest)
		return
	}

	// Get access token from request.
	accessToken := r.URL.Query().Get("access_token")
	if accessToken == "" {
		http.Error(w, "Access token not sending.", http.StatusBadRequest)
		return
	}

	refreshTokenAfterParse, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return app.jwtSecret, nil
	})

	if err != nil {
		http.Error(w, "Invalid refresh token.", http.StatusBadRequest)
		return
	}

	refreshTokenClaims, okR := refreshTokenAfterParse.Claims.(jwt.MapClaims)
	if !(okR && refreshTokenAfterParse.Valid) {
		http.Error(w, "Invalid refresh token.", http.StatusBadRequest)
		return
	}

	timestamp := refreshTokenClaims["exp"].(float64)
	if timestamp <= float64(time.Now().Unix()) {
		http.Error(w, "Refresh token expired.", http.StatusBadRequest)
		return
	}

	accessTokenAfterParse, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return app.jwtSecret, nil
	})

	if err != nil {
		http.Error(w, "Invalid refresh token.", http.StatusBadRequest)
		return
	}

	accessTokenClaims, okR := accessTokenAfterParse.Claims.(jwt.MapClaims)
	if !(okR && refreshTokenAfterParse.Valid) {
		http.Error(w, "Invalid refresh token.", http.StatusBadRequest)
		return
	}

	if accessTokenClaims["refresh_id"] != refreshTokenClaims["refresh_id"] {
		http.Error(w, "Difference refresh id between accessToken (%s) and refreshToken (%s).", http.StatusBadRequest)
		return
	}

	// Generate new access token.
	id := accessTokenClaims["refresh_id"].(string)
	userId := accessTokenClaims["user_id"].(string)
	newAccessToken, accessTokenGenerationError := app.generateAccessToken(userId, id)
	if accessTokenGenerationError != nil {
		http.Error(w, "Failed to generate Access token.", http.StatusInternalServerError)
		return
	}

	response := auth.RefreshTokenResponse{TokenType: "bearer", AccessToken: newAccessToken, ExpiresIn: app.accessTokenExpiration.Seconds()}

	marshal, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to convert json", http.StatusInternalServerError)
		return
	}

	_, writeBodyError := w.Write(marshal)
	if writeBodyError != nil {
		http.Error(w, "Failed to write in body", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

}
