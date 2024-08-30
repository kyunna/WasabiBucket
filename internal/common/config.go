package common

import (
	"github.com/joho/godotenv"
	"os"
)

type Config struct {
	NVDAPIKey string
	DBConfig  DBConfig
	AWSConfig AWSConfig
}

type DBConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
}

type AWSConfig struct {
	AccessKey		    string
	SecretAccessKey string
	Region          string
	SQSQueueURL     string
}

func LoadConfig() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, err
	}

	return &Config{
		NVDAPIKey: os.Getenv("NVD_API_KEY"),
		DBConfig: DBConfig {
			Host:     os.Getenv("DB_HOST"),
			Port:     os.Getenv("DB_PORT"),
			User:     os.Getenv("DB_USER"),
			Password: os.Getenv("DB_PASSWORD"),
			Name:     os.Getenv("DB_NAME"),
		},
		AWSConfig: AWSConfig {
			AccessKey:       os.Getenv("AWS_ACCESS_KEY"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			Region:          os.Getenv("AWS_REGION"),
			SQSQueueURL:     os.Getenv("SQS_QUEUE_URL"),
		},
	}, nil
}
