package common

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
)

type DatabaseConnector interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	Close() error
}

type PostgresConnector struct {
	*sql.DB
}

func (pc *PostgresConnector) Close() error {
	return pc.DB.Close()
}

type DatabaseInitializer interface {
	InitDatabase(config ConfigLoader) (DatabaseConnector, error)
}

type PostgresInitializer struct{}

func NewDatabaseInitializer() DatabaseInitializer {
	return &PostgresInitializer{}
}

func (p *PostgresInitializer) InitDatabase(config ConfigLoader) (DatabaseConnector, error) {
	dbConfig := config.GetDatabaseConfig()
	connectionString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=require",
		dbConfig.Host, 
		dbConfig.Port, 
		dbConfig.User, 
		dbConfig.Password, 
		dbConfig.Name)

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		db.Close()
		return nil, err
	}

	return &PostgresConnector{db}, nil
}
