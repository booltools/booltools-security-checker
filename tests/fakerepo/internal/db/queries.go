package db

import (
	"database/sql"
	"fmt"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) GetUserByID(userID string) (*User, error) {
	// SQL INJECTION: user input directly concatenated into query
	query := fmt.Sprintf("SELECT id, name, email FROM users WHERE id = '%s'", userID)
	row := r.db.QueryRow(query)

	var user User
	err := row.Scan(&user.ID, &user.Name, &user.Email)
	return &user, err
}

func (r *UserRepository) SearchUsers(searchTerm string) ([]User, error) {
	// SQL INJECTION: string interpolation in query
	query := "SELECT id, name, email FROM users WHERE name LIKE '%" + searchTerm + "%'"
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Name, &u.Email)
		users = append(users, u)
	}
	return users, nil
}

func (r *UserRepository) DeleteUser(userID string) error {
	// SQL INJECTION
	_, err := r.db.Exec("DELETE FROM users WHERE id = " + userID)
	return err
}

func (r *UserRepository) UpdateEmail(userID string, email string) error {
	// SAFE: using parameterized query
	_, err := r.db.Exec("UPDATE users SET email = $1 WHERE id = $2", email, userID)
	return err
}

type User struct {
	ID    int
	Name  string
	Email string
}
