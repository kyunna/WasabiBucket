package common

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Logger interface {
	LogPhaseStart(id string, phase string)
	Print(v ...interface{})
	Printf(format string, v ...interface{})
	Println(v ...interface{})
	Error(v ...interface{})
	Errorf(format string, v ...interface{})
	Errorln(v ...interface{})
	// Fatal(v ...interface{})
	// Fatalf(format string, v ...interface{})
	// Fatalln(v ...interface{})
}

func (f *FileLogger) Print(v ...interface{}) { f.checkDate(); f.infoLogger.Print(v...) }
func (f *FileLogger) Printf(format string, v ...interface{}) {
	f.checkDate()
	f.infoLogger.Printf(format, v...)
}
func (f *FileLogger) Println(v ...interface{}) { f.checkDate(); f.infoLogger.Println(v...) }

func (f *FileLogger) Error(v ...interface{}) { f.checkDate(); f.errorLogger.Print(v...) }
func (f *FileLogger) Errorf(format string, v ...interface{}) {
	f.checkDate()
	f.errorLogger.Printf(format, v...)
}
func (f *FileLogger) Errorln(v ...interface{}) { f.checkDate(); f.errorLogger.Println(v...) }

// func (f *FileLogger) Fatal(v ...interface{})                 { f.errorLogger.Fatal(v...) }
// func (f *FileLogger) Fatalf(format string, v ...interface{}) { f.errorLogger.Fatalf(format, v...) }
// func (f *FileLogger) Fatalln(v ...interface{})               { f.errorLogger.Fatalln(v...) }

type LoggerInitializer interface {
	InitLogger(appName string, config ConfigLoader) (Logger, error)
}

type FileLogger struct {
	infoLogger  *log.Logger
	errorLogger *log.Logger
	file        *os.File
	logDir      string
	currentDate string
}

func (f *FileLogger) Close() error {
	if f.file != nil {
		return f.file.Close()
	}
	return nil
}

func (f *FileLogger) checkDate() {
	currentDate := time.Now().Format("2006-01-02")
	if currentDate != f.currentDate {
		f.rotateLogFile(currentDate)
	}
}

func (f *FileLogger) rotateLogFile(currentDate string) {
	if f.file != nil {
		f.file.Close()
	}

	logFile, err := os.OpenFile(filepath.Join(f.logDir, currentDate+".log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open log file: %v\n", err)
		return
	}

	var writer io.Writer = logFile
	if f.infoLogger.Writer() == io.MultiWriter(f.file, os.Stdout) {
		writer = io.MultiWriter(logFile, os.Stdout)
	}

	f.infoLogger.SetOutput(writer)
	f.errorLogger.SetOutput(writer)
	f.file = logFile
	f.currentDate = currentDate
}

type FileLoggerInitializer struct{}

func NewLoggerInitializer() LoggerInitializer {
	return &FileLoggerInitializer{}
}

func (f *FileLoggerInitializer) InitLogger(appName string, config ConfigLoader) (Logger, error) {
	loggerConfig := config.GetLoggerConfig()
	logDir := filepath.Join(loggerConfig.BaseDir, appName)
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("Failed to create log directory: %w", err)
	}

	currentDate := time.Now().Format("2006-01-02")
	logFile, err := os.OpenFile(filepath.Join(logDir, currentDate+".log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("Failed to open log file: %w", err)
	}

	var writer io.Writer = logFile
	if loggerConfig.ConsoleOutput {
		writer = io.MultiWriter(logFile, os.Stdout)
	}

	infoLogger := log.New(writer, "[INFO] ", log.Ldate|log.Ltime)
	errorLogger := log.New(writer, "[ERROR] ", log.Ldate|log.Ltime)

	return &FileLogger{
		infoLogger:  infoLogger,
		errorLogger: errorLogger,
		file:        logFile,
		logDir:      logDir,
		currentDate: currentDate,
	}, nil
}

func (f *FileLogger) LogPhaseStart(id string, phase string) {
	f.checkDate()
	f.infoLogger.Printf("%s | ===== [%s] =====", id, strings.ToUpper(phase))
}
