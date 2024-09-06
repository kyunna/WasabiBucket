package collector

import (
	"fmt"
	"time"
	"io"
	"net/http"
	"net/url"
	"encoding/json"

	"wasabibucket/internal/common"
	"wasabibucket/pkg/models"
)

type Collector struct {
	config common.ConfigLoader
	db     common.DatabaseConnector
  logger common.Logger
	sqs    common.SQSPublisher
}

func NewCollector(config common.ConfigLoader) (*Collector, error) {
	dbInitializer := common.NewDatabaseInitializer()
	db, err := dbInitializer.InitDatabase(config)
	if err != nil {
		return nil, err
	}

	loggerInitializer := common.NewLoggerInitializer()
	logger, err := loggerInitializer.InitLogger("collector", config)
	if err != nil {
		db.Close()
		return nil, err
	}

	sqsInitializer := common.NewSQSPublisherInitializer()
	sqs, err := sqsInitializer.InitSQSPublisher(config)
	if err != nil {
		return nil, err
	}

	return &Collector{
		config: config,
		db:     db,
		logger: logger,
		sqs:    sqs,
	}, nil
}

// Collect CVE data
func (c *Collector) Run(startDate, endDate time.Time) error {
	nvdConfig:= c.config.GetNVDConfig()

	startIndex := 0
	totalResults := 0
	updateResults := 0

	c.logger.Printf("Fetching CVEs from %s to %s (GMT)\n", startDate.Format(time.RFC3339), endDate.Format(time.RFC3339))

	for {
		resp, err := fetchCVEData(nvdConfig, startDate, endDate, startIndex)
		if err != nil {
			return fmt.Errorf("[fetchCVEData] %w", err) 
		}

		for _, vuln := range resp.Vulnerabilities {
			changed, err := storeCVEData(c.db, vuln.Cve)
			if err != nil {
				c.logger.Errorf("[storeCVEData] %v\n", err)
				continue
			}

			if changed {
				c.logger.Printf("Update CVE data to DB: %s\n", vuln.Cve.ID)

				err = c.sqs.SendMessage(vuln.Cve.ID)
				if err != nil {
					c.logger.Errorf("[SendMessage] %v", err)
				} else {
					c.logger.Printf("Publish CVE update to SQS: %s", vuln.Cve.ID)
				}

				updateResults++
			}
		}

		totalResults = resp.TotalResults
		startIndex += resp.ResultsPerPage

		if startIndex >= totalResults {
			break
		}

		time.Sleep(6 * time.Second)
	}

	c.logger.Printf("Updated CVE : %d / %d\n", updateResults, totalResults)

	return nil
}

func fetchCVEData(config common.NVDConfig, startDate, endDate time.Time, startIndex int) (*models.NVDResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	params := url.Values{}
	params.Add("pubStartDate", startDate.Format(time.RFC3339))
	params.Add("pubEndDate", endDate.Format(time.RFC3339))
	params.Add("startIndex", fmt.Sprintf("%d", startIndex))
	params.Add("resultsPerPage", "100")

	req, err := http.NewRequest("GET", config.APIUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("apiKey", config.APIKey)
	req.URL.RawQuery = params.Encode()

	var resp *http.Response
	for retries := 0; retries < 3; retries++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(time.Duration(retries+1) * time.Second)
	}

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err 
	}

	var nvdResp models.NVDResponse
	err = json.Unmarshal(body, &nvdResp)
	if err != nil {
		return nil, err
	}

	return &nvdResp, nil
}

func (c *Collector) Close() error {
	var errs []error

	if err := c.db.Close(); err != nil {
		errs = append(errs, fmt.Errorf("Failed to close database: %w", err))
	}

	if fileLogger, ok := c.logger.(*common.FileLogger); ok {
		if err := fileLogger.Close(); err != nil {
			errs = append(errs, fmt.Errorf("Failed to close logger: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("Errors occurred while closing resources: %v", errs)
	}
	return nil
}
