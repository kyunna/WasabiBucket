// internal/common/config.go

package common

import (
    "github.com/joho/godotenv"
    "os"
)

type Config struct {
    NVDAPIKey string
    DBConfig  DBConfig
}

type DBConfig struct {
    Host     string
    Port     string
    User     string
    Password string
    Name     string
}

func LoadConfig() (*Config, error) {
    err := godotenv.Load()
    if err != nil {
        return nil, err
    }

    return &Config{
        NVDAPIKey: os.Getenv("NVD_API_KEY"),
        DBConfig: DBConfig{
            Host:     os.Getenv("DB_HOST"),
            Port:     os.Getenv("DB_PORT"),
            User:     os.Getenv("DB_USER"),
            Password: os.Getenv("DB_PASSWORD"),
            Name:     os.Getenv("DB_NAME"),
        },
    }, nil
}
