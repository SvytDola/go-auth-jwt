package main

import (
	"github.com/SvytDola/go-auth-jwt/internal"
	"github.com/joho/godotenv"
	"log"
	"os"
	"time"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}
	jwtSecret := []byte(os.Getenv(""))
	mongoDbUrl := os.Getenv("MONGODB_URI")
	mongoDbDatabase := os.Getenv("MONGODB_DB_NAME")

	app := internal.CreateApp(
		jwtSecret,
		time.Hour*24,
		time.Hour*24*7,
		mongoDbUrl,
		mongoDbDatabase,
	)

	err := app.Run(":8080", nil)
	if err != nil {
		panic(err)
	}
}
