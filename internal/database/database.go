package database

import (
	"encoding/json"
	"os"
)

const DB = "database.json"

type Chirp struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
}

func LoadChirpsDB(db string) ([]Chirp, error) {
	f, err := os.OpenFile(DB, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(f)
	chirps := []Chirp{}
	err = decoder.Decode(&chirps)
	if err != nil {
		return nil, err
	}
	return chirps, nil
}

func GetSingleChirp(chirpID int, db string) (Chirp, error) {
	chirps, err := LoadChirpsDB(db)
	if err != nil {
		return Chirp{}, err
	}

	for _, c := range chirps {
		if c.ID == chirpID {
			return c, nil
		}
	}

	return Chirp{}, nil
}

func SaveChirpsDB(chirps []Chirp, db string) error {
	dat, err := json.Marshal(chirps)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(db, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	_, err = f.Write(dat)
	return err
}
