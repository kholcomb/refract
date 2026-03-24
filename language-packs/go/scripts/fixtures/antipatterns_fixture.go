// Package fixtures contains intentional anti-patterns for testing detection.
// Do not use in production.
package fixtures

import (
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"os"
)

// ── defer in loop ──────────────────────────────────────────────────────────

func processFiles(paths []string) error {
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close() // antipattern: defer_in_loop
		_ = f
	}
	return nil
}

// ── errors.New(fmt.Sprintf(...)) ───────────────────────────────────────────

func validateAge(age int) error {
	if age < 0 {
		return errors.New(fmt.Sprintf("invalid age: %d", age)) // antipattern: error_string_format
	}
	return nil
}

// ── goroutine closure capture ──────────────────────────────────────────────

func launchWorkers(ids []int) {
	for _, id := range ids {
		go func() { // antipattern: goroutine_closure_capture
			fmt.Println(id)
		}()
	}
}

// ── TLS InsecureSkipVerify ─────────────────────────────────────────────────

func insecureClient() *tls.Config {
	return &tls.Config{ // antipattern: tls_insecure_skip
		InsecureSkipVerify: true,
	}
}

// ── SQL string concatenation ───────────────────────────────────────────────

func findUser(db *sql.DB, id string) (*sql.Row, error) {
	row := db.QueryRow("SELECT * FROM users WHERE id=" + id) // antipattern: sql_string_concat
	return row, nil
}

// ── weak rand in security context ──────────────────────────────────────────

func generateToken() string {
	// "token" variable name + rand.Intn triggers weak_rand
	token := fmt.Sprintf("%d", rand.Intn(999999)) // antipattern: weak_rand
	return token
}
