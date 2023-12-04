package database

import (
	"fmt"
	"time"
)

type Revocation struct {
	Token     string    `json:"token"`
	RevokedAt time.Time `json:"revoked_at"`
}

func (db *DB) RevokeRefreshToken(id string, expireTime time.Time) error {
	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	revocation := Revocation{
		Token:     id,
		RevokedAt: expireTime,
	}
	dbStructure.Revocations[id] = revocation
	if err := db.writeDB(dbStructure); err != nil {
		return fmt.Errorf("RevokeRefreshToken: failed to save db: %w", err)
	}

	return nil
}

func (db *DB) IsRevoked(token string) (bool, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return false, err
	}

	revocation, ok := dbStructure.Revocations[token]
	if !ok {
		return false, nil
	}

	if revocation.RevokedAt.IsZero() {
		return false, nil
	}

	return true, nil
}
