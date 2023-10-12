package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	type chirpMessage struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	chirp := chirpMessage{}
	err := decoder.Decode(&chirp)

	type errorMessage struct {
		Error string `json:"error"`
	}
	if err != nil {
		log.Printf("Error decoding Chirp: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		respBody := errorMessage{Error: "could not decode Chirp"}
		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Could not marshal error message: %s", err)
			return
		}
		w.Write(dat)
		w.Header().Set("Content-Type", "application/json")
		return
	}
	if len(chirp.Body) > 140 {
		respBody := errorMessage{Error: "Chirp is too long"}
		w.WriteHeader(http.StatusBadRequest)
		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Could not marhsal error message: %s", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(dat)
		return
	}
	type validResponse struct {
		Valid bool `json:"valid"`
	}
	respBody := validResponse{Valid: true}
	dat, err := json.Marshal(respBody)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(dat)

}
