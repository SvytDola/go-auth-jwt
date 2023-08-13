package internal

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/SvytDola/go-auth-jwt/internal/dto/auth"
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
	refreshTokenCollection *mongo.Collection
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
		refreshTokenCollection: collection,
	}
}

func (app *App) GetTokensHandler(w http.ResponseWriter, r *http.Request) {

	// Get user refreshId from request.
	userId := r.URL.Query().Get("user_id")

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
	inserted, err := app.refreshTokenCollection.InsertOne(context.TODO(), info)
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
	return http.ListenAndServe(addr, handler)
}
