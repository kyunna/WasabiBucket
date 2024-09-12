package main

import (
	"log"
	"time"

	"wasabibucket/internal/collector"
	"wasabibucket/internal/common"
)

func main() {
	config := common.NewConfig()
	err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	startDate, _ := time.Parse("2006-01-02T15:04:05.000", "2024-09-06T00:00:00.000")
	endDate, _ := time.Parse("2006-01-02T15:04:05.000", "2024-09-06T03:00:00.000")

	startDateGMT := startDate.UTC()
	endDateGMT := endDate.UTC()


	c, err := collector.New(config)
	if err != nil {
		log.Fatalf("Error creating collector: %v", err)
	}

	defer c.Close()
	err = c.Run(startDateGMT, endDateGMT)
	if err != nil {
		log.Fatalf("Error collecting CVE data: %v", err)
	}
}
