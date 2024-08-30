package common

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
)

type Database struct {
	*sql.DB
}

func InitDatabase(config *Config) (*Database, error) {
	connectionString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=require",
	config.DBConfig.Host, 
	config.DBConfig.Port, 
	config.DBConfig.User, 
	config.DBConfig.Password, 
	config.DBConfig.Name)

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return &Database{db}, nil
}
