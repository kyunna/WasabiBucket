// cmd/collector/main.go

package main

import (
    "log"
    "time"

    "wasabibucket/internal/collector"
    "wasabibucket/internal/common"
)

func main() {
    config, err := common.LoadConfig()
    if err != nil {
        log.Fatalf("Error loading configuration: %v", err)
    }

    db, err := common.InitDatabase(config)
    if err != nil {
        log.Fatalf("Error initializing database: %v", err)
    }
    defer db.Close()

    logger, err := common.InitLogger(config)
    if err != nil {
        log.Fatalf("Error initializing logger: %v", err)
    }

	// location, err := time.LoadLocation("Asia/Seoul")
	// if err != nil {
	// 	fmt.Printf("Error loading location: %v\n", err)
	// 	return
	// }

	// now := time.Now().In(location)
	// startDate := now.Add(-3 * time.Hour).Truncate(time.Hour)
	// endDate := now

    startDate, _ := time.Parse("2006-01-02T15:04:05.000", "2024-08-28T00:00:00.000")
    endDate, _ := time.Parse("2006-01-02T15:04:05.000", "2024-08-29T00:00:00.000")

    startDateGMT := startDate.UTC()
    endDateGMT := endDate.UTC()

    logger.Printf("Fetching CVEs from %s to %s (GMT)\n", startDateGMT.Format(time.RFC3339), endDateGMT.Format(time.RFC3339))

    err = collector.CollectCVEData(config, db, logger, startDateGMT, endDateGMT)
    if err != nil {
        logger.Fatalf("Error collecting CVE data: %v", err)
    }

    logger.Println("CVE data collection completed successfully")
}
