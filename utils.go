package utils

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/xo/dburl"
)

type User struct {
	Id int32 `json:"id"`
}

type JwtClaims struct {
	jwt.StandardClaims
	User User
}

/*
 * Validates the token and returns the JwtClaims.User claim
 */
func ValidateToken(token *jwt.Token) (User, bool) {
	claims, ok := token.Claims.(*JwtClaims)
	if ok && token.Valid {
		return claims.User, true
	}
	return User{Id: 0}, false
}

func ParseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		hmacSecret := os.Getenv("JWT_HS512_SECRET")
		return []byte(hmacSecret), nil
	})

	return token, err
}

func CreateToken(user User) (string, error) {
	iat := time.Now()
	exp := time.Now().Add(time.Hour * 24)
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"user": user,
		"iat":  iat.Unix(),
		"exp":  exp.Unix(),
	})

	secret, secretExists := os.LookupEnv("JWT_HS512_SECRET")

	if !secretExists {
		return "", errors.New("env var JWT_HS512_SECRET is not set")
	}

	tokenString, err := token.SignedString([]byte(secret))

	return tokenString, err
}

func DbConnect() (*sql.DB, error) {
	databaseUrl, isSetDatabaseUrl := os.LookupEnv("DATABASE_URL")

	if !isSetDatabaseUrl {
		log.Fatal("DATABASE_URL not defined.")
		return nil, nil
	}

	db, connectionError := dburl.Open(strings.TrimSuffix(databaseUrl, "?ssl-mode=REQUIRED"))

	return db, connectionError
}
