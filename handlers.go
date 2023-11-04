package main

import (
	"encoding/json"
	"errors"
	"fmt"
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

func (cfg *apiConfig) postUsersHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("error decoding User: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "could not decode user")
		return
	}

	if err != nil {
		log.Printf("decoding failed: %v\n", err)
		respondWithError(w, http.StatusBadRequest, "failed to decode user provided params")
		return
	}
	newUser, err := cfg.DB.CreateUser(params.Email, params.Password)
	if err != nil {
		log.Printf("could not save User: %v\n", err)
		respondWithError(w, http.StatusInternalServerError, "could not save new user")
		return
	}

	respondWithJSON(w, http.StatusCreated, newUser)
}

func (cfg *apiConfig) postLoginHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
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
			respondWithError(w, http.StatusNotFound, fmt.Sprintf("User with Email %s does not exist", params.Email))
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
	expiresInSeconds := params.ExpiresInSeconds
	if expiresInSeconds == 0 {
		expiresInSeconds = 24 * 60 * 60
	}
	token, err := createJWT(cfg.jwtSecret, user.ID, expiresInSeconds)
	if err != nil {
		log.Printf("failed to create token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "token creation failed")
	}

	respondWithJSON(w, http.StatusOK, user.GetUserWithToken(token))
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

func createJWT(secret string, id int, expirationTime int) (string, error) {
	currentTime := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(currentTime),
		ExpiresAt: jwt.NewNumericDate(currentTime.Add(time.Second * time.Duration(expirationTime))),
		Subject:   fmt.Sprintf("%d", id),
	})

	return token.SignedString([]byte(secret))
}
