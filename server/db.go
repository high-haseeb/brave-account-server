package server

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func checkErr(err error) {
	if err != nil {
		log.Println(err)
		log.Fatalln(err)
	}
}

var db *sql.DB

func InitDB() {
	var err error
	log.Println("INFO: Initializing the database")
	db, err = sql.Open("sqlite3", "./accounts.db")
	checkErr(err)
	// defer db.Close()

	createTable := `
    CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
	    name     TEXT NOT NULL,
	    email    TEXT UNIQUE NOT NULL,
	    password TEXT NOT NULL,
	    secret   TEXT NOT NULL,
	    token    TEXT,
	    verified BOOLEAN DEFAULT FALSE 
    );`
	_, err = db.Exec(createTable)
	checkErr(err)
}

func addUser(user User) bool {
	var exists bool
	log.Printf("Chekcing email %s if it already exists.\n", user.Email)

	existsQuery := `SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)`
	if err := db.QueryRow(existsQuery, user.Email).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			log.Println("ERROR: there are no rows")
		} else {
			log.Println("ERROR: can not check if the user exists")
			return true
		}
	}

	if exists {
		log.Printf("User with email %s already exists. Skipping addition.\n", user.Email)
		return true
	}
	query := `INSERT INTO users (name, email, password, secret, token, verified) VALUES (?, ?, ?, ?, ?, ?)`
	_, err := db.Exec(query, user.Name, user.Email, user.Password, user.Secret, user.Token, user.Verified)
	checkErr(err)
	return false
}

func verifyUser(token string) (bool, error) {
	query := `UPDATE users SET verified = TRUE WHERE token = ?`
	res, err := db.Exec(query, token)
	if err != nil {
		return false, err
	}

	// Check if any rows were affected (i.e., if the user was found)
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}

	return affected > 0, nil
}

func getUserData(email, password string) (string, string, error) {
	var secret string
	var name string
	var verified bool
	query := `SELECT secret, name, verified
	          FROM users 
	          WHERE email = ? AND password = ?`

	err := db.QueryRow(query, email, password).Scan(&secret, &name, &verified)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", fmt.Errorf("ERROR: no user found with the provided email and password")
		}
		return "", "", err
	}

	if !verified {
		return "", "", fmt.Errorf("ERROR: user is not verified")
	}

	return secret, name, nil
}

func getUserToken(email string) (string, error) {
	var token string
	query := `SELECT token
	          FROM users 
	          WHERE email = ?`

	err := db.QueryRow(query, email).Scan(&token)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("ERROR: no user found with the provided email")
		}
		return "", err
	}

	return token, nil
}

func updateUserPassword(email, token, password string) error {
	validToken, err := getUserToken(email)
	if err != nil {
		return err
	}
	if validToken != token {
		return fmt.Errorf("ERROR: invalid token for the user")
	}

	query := `UPDATE users 
	          SET password = ? 
	          WHERE email = ?`

	_, err = db.Exec(query, password, email)
	if err != nil {
		return fmt.Errorf("ERROR: failed to update password: %v", err)
	}
	return nil
}
