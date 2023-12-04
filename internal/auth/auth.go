package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	AccessIssuer  = "chirpy-access"
	RefreshIssuer = "chirpy-refresh"
)

var ErrNoAuthHeaderIncluded = errors.New("not auth header included in request")

func CreateJWT(secret string, id int, expirationTime time.Duration, issuer string) (string, error) {
	currentTime := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(currentTime),
		ExpiresAt: jwt.NewNumericDate(currentTime.Add(expirationTime)),
		Subject:   fmt.Sprintf("%d", id),
	})

	return token.SignedString([]byte(secret))
}

func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func RefreshToken(tokenString, tokenSecret string) (string, error) {
	claimsStruct := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		&claimsStruct,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(tokenSecret), nil
		},
	)
	if err != nil {
		return "", err
	}

	userIDString, err := token.Claims.GetSubject()
	if err != nil {
		return "", err
	}

	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		return "", err
	}

	if issuer != RefreshIssuer {
		return "", errors.New("invalid issuer")
	}

	userID, err := strconv.Atoi(userIDString)
	if err != nil {
		return "", err
	}

	newToken, err := CreateJWT(
		tokenSecret,
		userID,
		time.Hour,
		AccessIssuer,
	)
	if err != nil {
		return "", err
	}
	return newToken, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	return getAuth(headers, "Bearer")
}

func GetAPIKey(headers http.Header) (string, error) {
	return getAuth(headers, "ApiKey")
}

func getAuth(headers http.Header, authType string) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}
	splitAuth := strings.Split(authHeader, " ")
	if len(splitAuth) < 2 || splitAuth[0] != authType {
		return "", errors.New("malformed authorization header")
	}
	return splitAuth[1], nil

}
