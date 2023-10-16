package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
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

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}
	type returnVals struct {
		CleanedBody string `json:"cleaned_body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)

	if err != nil {
		log.Printf("Error decoding Chirp: %s", err)
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
	respondWithJSON(w, http.StatusOK, returnVals{cleanedChirp})

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
