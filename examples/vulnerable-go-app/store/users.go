// The data access layer of the Go example: the dangerous query lives here, one call away from the handler.
package store

import "database/sql"

var db *sql.DB

type User struct {
	ID    int
	Email string
}

// FindUserByEmail builds the query from text: a handler that passes the request's value in is vulnerable.
func FindUserByEmail(email string) *User {
	row := db.QueryRow("SELECT id, email FROM users WHERE email = '" + email + "'")
	var u User
	if err := row.Scan(&u.ID, &u.Email); err != nil {
		return nil
	}
	return &u
}
