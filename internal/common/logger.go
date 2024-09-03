package common

import (
	"log"
	"os"
	"path/filepath"
	"time"
)

type Logger struct {
	*log.Logger
}

func InitLogger(appName string, config *Config) (*Logger, error) {
	logDir := filepath.Join(".", "log", appName)
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		return nil, err
	}

	currentDate := time.Now().Format("2006-01-02")
	logFile, err := os.OpenFile(filepath.Join(logDir, currentDate+".log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		return nil, err
	}

	logger := log.New(logFile, "", log.Ldate|log.Ltime|log.Lshortfile)
	return &Logger{logger}, nil
}
