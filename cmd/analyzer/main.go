package main

import (
	"log"

	"wasabibucket/internal/analyzer"
	"wasabibucket/internal/common"
)

func main() {
	config, err := common.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	logger, err := common.InitLogger("analyzer", config)
	if err != nil {
		log.Fatalf("Error initializing logger: %v", err)
	}

	a, err := analyzer.New(config)
	if err != nil {
		log.Fatalf("Error creating analyzer: %v", err)
	}

	logger.Fatal("Analyzer Starting...")

	if err := a.Run(); err != nil {
		logger.Fatalf("Error starting analyzer: %v", err)
	}
}
