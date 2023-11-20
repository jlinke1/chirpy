package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jlinke1/chirpy/internal/database"
	"golang.org/x/crypto/bcrypt"
)

const (
	accessExpirationTime  = 60 * 60
	refreshExpirationTime = 60 * 24 * 60 * 60
	accessIssuer          = "chirpy-access"
	refreshIssuer         = "chirpy-refresh"
)

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func (cfg *apiConfig) hitsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`<html>

<body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
</body>

</html>
`, cfg.fileServerHits)))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	cfg.fileServerHits = 0
	w.Write([]byte("Hits reset to 0"))
}

func (cfg *apiConfig) postChirpsHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding Chirp: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "could not decode Chirp")
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	// using this as a set! for fast membership checks
	badWords := map[string]struct{}{"kerfuffle": {}, "sharbert": {}, "fornax": {}}
	cleanedChirp := replaceBadWords(params.Body, badWords)

	newChirp, err := cfg.DB.CreateChirp(cleanedChirp)
	if err != nil {
		log.Printf("could not save chirps: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "could not save new chirp")
	}

	respondWithJSON(w, http.StatusCreated, newChirp)
}

func decodeUserRequest(data io.Reader) (string, string, error) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(data)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		return "", "", fmt.Errorf("decodeUserRequest: failed to decode: %w", err)
	}

	return params.Email, params.Password, nil
}

func (cfg *apiConfig) postUsersHandler(w http.ResponseWriter, r *http.Request) {
	email, password, err := decodeUserRequest(r.Body)

	if err != nil {
		log.Printf("decoding failed: %v\n", err)
		respondWithError(w, http.StatusBadRequest, "failed to decode user provided params")
		return
	}

	newUser, err := cfg.DB.CreateUser(email, password)
	if err != nil {
		log.Printf("could not save User: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "could not save new user")
		return
	}

	respondWithJSON(w, http.StatusCreated, newUser)
}

func extractClaims(r *http.Request, secret string) (string, *jwt.RegisteredClaims, error) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	parsedToken, err := jwt.ParseWithClaims(
		token,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		})
	if err != nil {
		return "", nil, fmt.Errorf("extractClaims: failed to parse token %w", err)
	}

	claims := parsedToken.Claims.(*jwt.RegisteredClaims)

	return token, claims, nil
}

func (cfg *apiConfig) putUsersHandler(w http.ResponseWriter, r *http.Request) {
	_, claims, err := extractClaims(r, cfg.jwtSecret)
	if err != nil {
		log.Printf("putUsersHandler: failed to parse token: %v", err)
		respondWithError(w, http.StatusUnauthorized, "token invalid")
	}
	issuer, err := claims.GetIssuer()
	if issuer == refreshIssuer {
		respondWithError(w, http.StatusUnauthorized, "provide an access token not a refresh token")
	}
	if err != nil {
		log.Printf("putUsersHandler: failed to get issuer: %v", err)
		respondWithError(w, http.StatusInternalServerError, "oh boy!")
	}

	userID, err := claims.GetSubject()
	if err != nil {
		log.Printf("putUsersHandler: failed to get UserID: %v", err)
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	id, err := strconv.Atoi(userID)
	if err != nil {
		log.Printf("putUsersHandler: failed to parse ID: %v", err)
		respondWithError(w, http.StatusInternalServerError, "invalid ID")
		return
	}

	newEmail, newPassword, err := decodeUserRequest(r.Body)
	if err != nil {
		log.Printf("putUsersHandler: decoding request failed: %v\n", err)
		respondWithError(w, http.StatusBadRequest, "failed to decode user provided params")
		return
	}

	updatedUser, err := cfg.DB.UpdateUser(id, newEmail, newPassword)
	if err != nil {
		log.Printf("putUsersHandler: updating user failed: %v", err)
		respondWithError(w, http.StatusInternalServerError, "update failed")
	}

	respondWithJSON(w, http.StatusOK, updatedUser)

}

func (cfg *apiConfig) postLoginHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("decoding failed: %v\n", err)
		respondWithError(w, http.StatusBadRequest, "failed to decode user provided params")
		return
	}

	user, err := cfg.DB.GetUserByMail(params.Email)
	if err != nil {
		log.Printf("Could not get user: %v\n", err)
		if errors.Is(err, database.ErrNotExist) {
			respondWithError(
				w,
				http.StatusNotFound,
				fmt.Sprintf("User with Email %s does not exist", params.Email),
			)
			return
		}
		respondWithError(w, http.StatusInternalServerError, "could not get user")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(params.Password))
	if err != nil {
		log.Printf("password comparison failed: %v", err)
		respondWithError(w, http.StatusUnauthorized, "wrong password")
		return
	}
	accessToken, err := createJWT(cfg.jwtSecret, user.ID, accessExpirationTime, accessIssuer)
	if err != nil {
		log.Printf("failed to create token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "token creation failed")
	}

	refreshToken, err := createJWT(cfg.jwtSecret, user.ID, refreshExpirationTime, refreshIssuer)
	if err != nil {
		log.Printf("failed to create token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "token creation failed")
	}

	respondWithJSON(w, http.StatusOK, user.GetUserWithTokens(accessToken, refreshToken))
}

func (cfg *apiConfig) postRefreshHandler(w http.ResponseWriter, r *http.Request) {
	tokenID, claims, err := extractClaims(r, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "retry later")
	}
	issuer, err := claims.GetIssuer()
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid token")
	}
	if issuer != refreshIssuer {
		respondWithError(w, http.StatusUnauthorized, "wrong token type")
	}
	_, err = cfg.DB.GetRefreshToken(tokenID)
	if !errors.Is(err, database.ErrNotExist) {
		respondWithError(w, http.StatusUnauthorized, "token already revoked")
	}
	userID, err := claims.GetSubject()
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid token")
	}
	id, err := strconv.Atoi(userID)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid token")
	}
	newToken, err := createJWT(cfg.jwtSecret, id, accessExpirationTime, accessIssuer)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}
	respondWithJSON(w, http.StatusOK, map[string]string{"token": newToken})
}

func (cfg *apiConfig) postRevokeHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := extractClaims(r, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "retry later")
	}
	err = cfg.DB.RevokeRefreshToken(token, time.Now())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "oh man")
	}

	w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.DB.GetChirps()
	if err != nil {
		log.Printf("could not load chirps: %v", err)
		respondWithError(w, http.StatusInternalServerError, "could not load chirps")
		return
	}
	respondWithJSON(w, http.StatusOK, chirps)

}

func (cfg *apiConfig) getSingleChirpHandler(w http.ResponseWriter, r *http.Request) {
	chirpID, err := strconv.Atoi(chi.URLParam(r, "chirpID"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid chirpID")
	}

	chirp, err := cfg.DB.GetChirp(chirpID)
	if errors.Is(err, database.ErrNotExist) {
		respondWithError(w, http.StatusNotFound, "Chirp does not exist")
		return
	}
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "couldn't get Chirp from DB")
		return
	}

	respondWithJSON(w, http.StatusOK, chirp)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	if code > 499 {
		log.Printf("Responding with 5XX error: %s", msg)
	}
	type errorMessage struct {
		Error string `json:"error"`
	}
	respondWithJSON(w, code, errorMessage{msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	w.Write(dat)
}

func replaceBadWords(chirp string, badWords map[string]struct{}) string {
	wordsInChirp := strings.Fields(chirp)
	for i, word := range wordsInChirp {
		wordLower := strings.ToLower(word)
		if _, ok := badWords[wordLower]; ok {
			wordsInChirp[i] = "****"
		}
	}
	return strings.Join(wordsInChirp, " ")
}

func createJWT(secret string, id int, expirationTime int, issuer string) (string, error) {
	currentTime := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(currentTime),
		ExpiresAt: jwt.NewNumericDate(currentTime.Add(time.Second * time.Duration(expirationTime))),
		Subject:   fmt.Sprintf("%d", id),
	})

	return token.SignedString([]byte(secret))
}
