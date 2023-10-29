package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

var ErrNotExist = errors.New("resource does not exist")

type DB struct {
	path string
	mu   *sync.RWMutex
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

type Chirp struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
}

type User struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
}

func NewDB(path string) (*DB, error) {
	db := &DB{
		path: path,
		mu:   &sync.RWMutex{},
	}
	err := db.ensureDB()
	return db, err
}

func (db *DB) CreateChirp(body string) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	id := len(dbStructure.Chirps) + 1
	chirp := Chirp{
		ID:   id,
		Body: body,
	}
	dbStructure.Chirps[id] = chirp

	err = db.writeDB(dbStructure)
	if err != nil {
		return Chirp{}, fmt.Errorf("CreateChirp: could not write db: %w", err)
	}

	return chirp, nil
}

func (db *DB) createDB() error {
	dbstructure := DBStructure{
		Chirps: map[int]Chirp{},
		Users:  map[int]User{},
	}
	return db.writeDB(dbstructure)
}

func (db *DB) ensureDB() error {
	_, err := os.ReadFile(db.path)
	if errors.Is(err, os.ErrNotExist) {
		return db.createDB()
	}
	return err
}

func (db *DB) loadDB() (DBStructure, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	dbstructure := DBStructure{}
	dat, err := os.ReadFile(db.path)
	if errors.Is(err, os.ErrNotExist) {
		return dbstructure, err
	}
	err = json.Unmarshal(dat, &dbstructure)
	if err != nil {
		return dbstructure, err
	}
	return dbstructure, nil
}

func (db *DB) writeDB(dbstructure DBStructure) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	dat, err := json.Marshal(dbstructure)
	if err != nil {
		return fmt.Errorf("writeDB: could not marshal dbstructure: %w", err)
	}

	err = os.WriteFile(db.path, dat, 0600)
	if err != nil {
		return fmt.Errorf("writeDB: couldn't write file: %w", err)
	}

	return nil
}

func (db DB) Load() (DBStructure, error) {
	f, err := os.OpenFile(db.path, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		return DBStructure{}, fmt.Errorf("Load: could not open file: %w", err)
	}
	decoder := json.NewDecoder(f)
	database := DBStructure{}
	err = decoder.Decode(&database)
	if err != nil {
		return DBStructure{}, fmt.Errorf("Load: could not decode database: %w", err)
	}

	return database, nil
}

func (db DB) GetChirps() ([]Chirp, error) {
	database, err := db.Load()
	if err != nil {
		return nil, fmt.Errorf("GetAllChrips: could not load data: %w", err)
	}

	chirps := make([]Chirp, 0, len(database.Chirps))
	for _, chirp := range database.Chirps {
		chirps = append(chirps, chirp)
	}
	return chirps, nil
}

func (db DB) GetChirp(chirpID int) (Chirp, error) {
	data, err := db.Load()
	if err != nil {
		return Chirp{}, fmt.Errorf("GetSingleChirp: could not load db: %w", err)
	}

	chirp, ok := data.Chirps[chirpID]
	if !ok {
		return Chirp{}, ErrNotExist
	}

	return chirp, nil
}

func (db DB) Save(chirps []Chirp) error {
	dat, err := json.Marshal(chirps)
	if err != nil {
		return fmt.Errorf("Save: could not marshal chirps: %w", err)
	}
	f, err := os.OpenFile(db.path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("Save: could not open db file: %w", err)
	}
	_, err = f.Write(dat)
	if err != nil {
		return fmt.Errorf("Save: could not save database: %w", err)
	}
	return nil
}
