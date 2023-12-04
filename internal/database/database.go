package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var ErrNotExist = errors.New("resource does not exist")

type DB struct {
	path string
	mu   *sync.RWMutex
}

type DBStructure struct {
	Chirps      map[int]Chirp            `json:"chirps"`
	Users       map[int]UserWithPassword `json:"users"`
	Revocations map[string]Revocation    `json:"revocations"`
}

type Chirp struct {
	ID       int    `json:"id"`
	Body     string `json:"body"`
	AuthorID int    `json:"author_id"`
}

type User struct {
	ID          int    `json:"id"`
	Email       string `json:"email"`
	IsChirpyRed bool   `json:"is_chirpy_red"`
}

type UserWithPassword struct {
	ID          int    `json:"id"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	IsChirpyRed bool   `json:"is_chirpy_red"`
}

type UserWithToken struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	IsChirpyRed  bool   `json:"is_chirpy_red"`
}

func (u UserWithPassword) GetUserWithoutPW() User {
	return User{ID: u.ID, Email: u.Email}
}

func (u UserWithPassword) GetUserWithTokens(token, refreshToken string) UserWithToken {
	return UserWithToken{
		ID:           u.ID,
		Email:        u.Email,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  u.IsChirpyRed,
	}
}

func NewDB(path string) (*DB, error) {
	db := &DB{
		path: path,
		mu:   &sync.RWMutex{},
	}
	err := db.ensureDB()
	return db, err
}

func (db *DB) CreateChirp(body string, authorID int) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	id := len(dbStructure.Chirps) + 1
	chirp := Chirp{
		ID:       id,
		Body:     body,
		AuthorID: authorID,
	}
	dbStructure.Chirps[id] = chirp

	err = db.writeDB(dbStructure)
	if err != nil {
		return Chirp{}, fmt.Errorf("CreateChirp: could not write db: %w", err)
	}

	return chirp, nil
}

func (db *DB) CreateUser(email string, password string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, fmt.Errorf("CreateUser: could not load db: %w", err)
	}

	encryptedPW, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return User{}, fmt.Errorf("CreateUser: failed to encrypt password: %w", err)
	}

	id := len(dbStructure.Users) + 1
	userPW := UserWithPassword{
		ID:       id,
		Email:    email,
		Password: string(encryptedPW),
	}
	dbStructure.Users[id] = userPW

	err = db.writeDB(dbStructure)
	if err != nil {
		return User{}, fmt.Errorf("CreateUser: could not write db: %w", err)
	}
	return userPW.GetUserWithoutPW(), nil
}

func (db *DB) UpdateUser(id int, newEmail, newPassword string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, fmt.Errorf("UpdateUser: failed to load db: %w", err)
	}

	encryptedPW, err := bcrypt.GenerateFromPassword([]byte(newPassword), 10)
	if err != nil {
		return User{}, fmt.Errorf("UpdateUser: failed to encrypt password: %w", err)
	}

	userPW := dbStructure.Users[id]
	userPW.Email = newEmail
	userPW.Password = string(encryptedPW)
	dbStructure.Users[id] = userPW
	if err := db.writeDB(dbStructure); err != nil {
		return User{}, fmt.Errorf("UpdateUser: failed to save db: %w", err)
	}

	return userPW.GetUserWithoutPW(), nil
}

func (db *DB) UpgradeUser(id int) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return fmt.Errorf("UpgradeUser: failed to load db: %w", err)
	}

	user, ok := dbStructure.Users[id]
	if !ok {
		return ErrNotExist
	}

	user.IsChirpyRed = true
	dbStructure.Users[user.ID] = user
	if err := db.writeDB(dbStructure); err != nil {
		return fmt.Errorf("UpgradeUser: failed to savs db: %w", err)
	}
	return nil
}

func (db *DB) createDB() error {
	dbstructure := DBStructure{
		Chirps:      map[int]Chirp{},
		Users:       map[int]UserWithPassword{},
		Revocations: map[string]Revocation{},
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

func (db *DB) GetChirpsByAuthor(authorID int) ([]Chirp, error) {
	database, err := db.Load()
	if err != nil {
		return nil, fmt.Errorf("GetChirpsByAuthor: could not load database: %w", err)
	}

	chirps := []Chirp{}
	for _, chirp := range database.Chirps {
		if chirp.AuthorID == authorID {
			chirps = append(chirps, chirp)
		}
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

func (db DB) DeleteChirp(chirpID int) error {
	data, err := db.Load()
	if err != nil {
		return fmt.Errorf("DeleteChirp: could not load DB: %w", err)
	}

	delete(data.Chirps, chirpID)
	return nil
}

func (db DB) GetRefreshToken(tokenID string) (time.Time, error) {
	data, err := db.Load()
	if err != nil {
		return time.Time{}, fmt.Errorf("GetRefreshToke: could not load db: %w", err)
	}

	revokecation, ok := data.Revocations[tokenID]
	if !ok {
		return time.Time{}, ErrNotExist
	}

	return revokecation.RevokedAt, nil
}

func (db DB) GetUserByMail(email string) (UserWithPassword, error) {
	data, err := db.Load()
	if err != nil {
		return UserWithPassword{}, fmt.Errorf("GetUserByMail: could not load data: %w", err)
	}

	for _, user := range data.Users {
		if user.Email == email {
			return user, nil
		}
	}
	return UserWithPassword{}, ErrNotExist
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
