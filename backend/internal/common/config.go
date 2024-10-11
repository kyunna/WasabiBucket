package common

import (
	"fmt"
	"github.com/joho/godotenv"
	"os"
	"strconv"
	"strings"
)

type ConfigLoader interface {
	Load() error
	GetLoggerConfig() LoggerConfig
	GetNVDConfig() NVDConfig
	GetDatabaseConfig() DatabaseConfig
	GetSQSConfig() SQSConfig
	GetGPTAPIKey() string
}

type Config struct {
	Logger    LoggerConfig
	NVD       NVDConfig
	Database  DatabaseConfig
	SQS       SQSConfig
	GPTAPIKey string
}

type LoggerConfig struct {
	BaseDir       string
	ConsoleOutput bool
}

type NVDConfig struct {
	APIKey string
	APIUrl string
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
}

type SQSConfig struct {
	AccessKey       string
	SecretAccessKey string
	Region          string
	QueueURL        string
}

func NewConfig() ConfigLoader {
	return &Config{}
}

func (c *Config) Load() error {
	err := godotenv.Load()
	if err != nil {
		return fmt.Errorf("failed to load .env file: %w", err)
	}

	c.Logger = LoggerConfig{
		BaseDir: getEnv("BASE_DIR", "./log"),
		ConsoleOutput: getEnvBool("CONSOLE_OUTPUT", false),
	}
	c.NVD = NVDConfig{
		APIUrl: getEnv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
		APIKey: getEnv("NVD_API_KEY", ""),
	}
	c.Database = DatabaseConfig{
		Host:     getEnv("DB_HOST", "localhost"),
		Port:     getEnv("DB_PORT", "5432"),
		User:     getEnv("DB_USER", ""),
		Password: getEnv("DB_PASSWORD", ""),
		Name:     getEnv("DB_NAME", ""),
	}
	c.SQS = SQSConfig{
		AccessKey:       getEnv("AWS_ACCESS_KEY", ""),
		SecretAccessKey: getEnv("AWS_SECRET_ACCESS_KEY", ""),
		Region:          getEnv("AWS_REGION", "us-west-2"),
		QueueURL:        getEnv("SQS_QUEUE_URL", ""),
	}
	c.GPTAPIKey = getEnv("GPT_API_KEY", "")

	if err := c.validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	return nil
}

func (c *Config) GetLoggerConfig() LoggerConfig {
	return c.Logger
}

func (c *Config) GetNVDConfig() NVDConfig {
	return c.NVD
}

func (c *Config) GetDatabaseConfig() DatabaseConfig {
	return c.Database
}

func (c *Config) GetSQSConfig() SQSConfig {
	return c.SQS
}

func (c *Config) GetGPTAPIKey() string {
	return c.GPTAPIKey
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		parsedValue, err := strconv.ParseBool(strings.ToLower(value))
		if err != nil {
			return fallback
		}
		return parsedValue
	}
	return fallback
}

func (c *Config) validate() error {
	if c.NVD.APIKey == "" {
		return fmt.Errorf("NVD API Key is required")
	}
	if c.Database.Host == "" || c.Database.Port == "" || c.Database.User == "" {
		return fmt.Errorf("Database configuration is incomplete")
	}
	if c.SQS.AccessKey == "" || c.SQS.SecretAccessKey == "" {
		return fmt.Errorf("AWS credentials are missing")
	}
	if c.GPTAPIKey == "" {
		return fmt.Errorf("GPT API Key is required")
	}
	return nil
}
