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
	"github.com/jlinke1/chirpy/internal/auth"
	"github.com/jlinke1/chirpy/internal/database"
)

const (
	accessExpirationTime  = time.Hour
	refreshExpirationTime = 60 * 24 * time.Hour
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
	id, err := cfg.extractUserID(r)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			respondWithError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
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

	newChirp, err := cfg.DB.CreateChirp(cleanedChirp, id)
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

func (cfg *apiConfig) parseToken(token string) (*jwt.RegisteredClaims, error) {
	parsedToken, err := jwt.ParseWithClaims(
		token,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.jwtSecret), nil
		})
	if err != nil {
		return nil, fmt.Errorf("parseToken: failed to parse token %w", err)
	}

	claims := parsedToken.Claims.(*jwt.RegisteredClaims)
	return claims, nil
}

func (cfg *apiConfig) extractClaims(r *http.Request) (string, *jwt.RegisteredClaims, error) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims, err := cfg.parseToken(token)
	if err != nil {
		return "", nil, fmt.Errorf("extractClaims: failed: %w", err)
	}

	return token, claims, nil
}

func (cfg *apiConfig) extractUserID(r *http.Request) (int, error) {
	_, claims, err := cfg.extractClaims(r)
	if err != nil {
		return 0, fmt.Errorf("extractUserID: failed to extract claims: %w", err)
	}
	issuer, err := claims.GetIssuer()
	if issuer == auth.RefreshIssuer {
		return 0, ErrUnauthorized
	}
	if err != nil {
		return 0, fmt.Errorf("extractUserID: failed to get issuer: %w", err)
	}

	userID, err := claims.GetSubject()
	if err != nil {
		return 0, fmt.Errorf("extractUserID: failed to get UserID: %w", err)
	}

	id, err := strconv.Atoi(userID)
	if err != nil {
		return 0, fmt.Errorf("extractUserID:failed to parse ID: %w", err)
	}
	return id, nil
}

func (cfg *apiConfig) putUsersHandler(w http.ResponseWriter, r *http.Request) {
	id, err := cfg.extractUserID(r)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			respondWithError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
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
	err = auth.CheckPasswordHash(params.Password, user.Password)
	if err != nil {
		log.Printf("password comparison failed: %v", err)
		respondWithError(w, http.StatusUnauthorized, "wrong password")
		return
	}
	accessToken, err := auth.CreateJWT(cfg.jwtSecret, user.ID, accessExpirationTime, auth.AccessIssuer)
	if err != nil {
		log.Printf("failed to create token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "token creation failed")
	}

	refreshToken, err := auth.CreateJWT(cfg.jwtSecret, user.ID, refreshExpirationTime, auth.RefreshIssuer)
	if err != nil {
		log.Printf("failed to create token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "token creation failed")
	}

	respondWithJSON(w, http.StatusOK, user.GetUserWithTokens(accessToken, refreshToken))
}

func (cfg *apiConfig) postRefreshHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Couldn't find JWT")
		return
	}

	isRevoked, err := cfg.DB.IsRevoked(refreshToken)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "could not check tokens")
		return
	}
	if isRevoked {
		respondWithError(w, http.StatusUnauthorized, "token already revoked")
		return
	}

	newToken, err := auth.RefreshToken(refreshToken, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid token")
	}
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
	}
	respondWithJSON(w, http.StatusOK, map[string]string{"token": newToken})
}

func (cfg *apiConfig) postRevokeHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := cfg.extractClaims(r)
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
	sort := r.URL.Query().Get("sort")
	descending := sort == "desc"

	authorID := r.URL.Query().Get("author_id")
	if authorID != "" {
		parsedAuthorID, err := strconv.Atoi(authorID)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "invalid authorID")
			return
		}
		chirps, err := cfg.DB.GetChirpsByAuthor(parsedAuthorID, descending)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "could not load chirps by author")
			return
		}
		respondWithJSON(w, http.StatusOK, chirps)
		return
	}

	chirps, err := cfg.DB.GetChirps(descending)
	if err != nil {
		log.Printf("could not load chirps: %v", err)
		respondWithError(w, http.StatusInternalServerError, "could not load chirps")
		return
	}
	respondWithJSON(w, http.StatusOK, chirps)

}

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	accessToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	claims, err := cfg.parseToken(accessToken)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "tststs")
	}

	chirpID, err := strconv.Atoi(chi.URLParam(r, "chirpID"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid chripID")
		return
	}

	chirp, err := cfg.DB.GetChirp(chirpID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("there is no Chirp with ID %d", chirpID))
	}

	user, err := claims.GetSubject()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	if user != strconv.Itoa(chirp.AuthorID) {
		respondWithError(w, http.StatusForbidden, "you are not the author of this chirp")
		return
	}
	err = cfg.DB.DeleteChirp(chirpID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "could not delete chirp")
	}
	w.WriteHeader(http.StatusOK)
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

func (cfg *apiConfig) postPolkaWebhooksHandler(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil || apiKey != cfg.polkaAPIKey {
		respondWithError(w, http.StatusUnauthorized, "invalid apiKey")
		return
	}

	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID int `json:"user_id"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(r.Body)
	var params parameters
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "failed to parse parameters")
		return
	}

	if params.Event != "user.upgraded" {
		respondWithJSON(w, http.StatusOK, nil)
	}

	err = cfg.DB.UpgradeUser(params.Data.UserID)
	if errors.Is(err, database.ErrNotExist) {
		respondWithError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "something went wrong")
		return
	}

	respondWithJSON(w, http.StatusOK, nil)
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

var ErrUnauthorized = errors.New("Unauthorized: invalid token")
