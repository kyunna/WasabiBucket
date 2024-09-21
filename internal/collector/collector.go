package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"wasabibucket/internal/common"
	"wasabibucket/internal/models"

	"github.com/lib/pq"
)

type Collector struct {
	config common.ConfigLoader
	db     common.DatabaseConnector
	logger common.Logger
	sqs    common.SQSPublisher
}

func New(config common.ConfigLoader) (*Collector, error) {
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

func (c *Collector) Run(ctx context.Context, interval int) error {
	c.logger.Printf("Start collector with interval %d hours\n", interval)

	defaultInterval := time.Duration(interval) * time.Hour

	const firstInterval = 10 * time.Second

	ticker := time.NewTicker(firstInterval)
	defer ticker.Stop()

	firstRun := true

	for {
		select {
		case <-ctx.Done():
			c.logger.Printf("Shutdown signal received, stopping collector...")
			return nil
		case <-ticker.C:
			if firstRun {
				ticker.Reset(defaultInterval)
				firstRun = false
			}

			// Manual date range for data collection
			// manualStartDate := time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC)
			// manualEndDate := time.Date(2024, 10, 1, 0, 0, 0, 0, time.UTC)
			// Use manual dates
			// startDate := manualStartDate
			// endDate := manualEndDate

			// c.logger.Printf("Using manual date range for data collection")

			// Comment out the automatic date calculation
			endDate := time.Now().UTC()
			startDate := endDate.AddDate(0, 0, -60)

			nvdConfig := c.config.GetNVDConfig()

			startIndex := 0
			totalResults := 0
			updateResults := 0

			c.logger.Printf("Fetching CVEs from %s to %s (UTC)\n", startDate.Format(time.RFC3339), endDate.Format(time.RFC3339))

			for {
				if totalResults > 0 {
					c.logger.Printf("Search Index : %d / %d", startIndex, totalResults)
				}

				resp, err := fetchCVEData(nvdConfig, startDate, endDate, startIndex)
				if err != nil {
					c.logger.Errorf("[fetchCVEData] %v", err)
					break
				}

				for _, vuln := range resp.Vulnerabilities {
					changed, err := storeCVEData(c.db, vuln.Cve)
					if err != nil {
						c.logger.Errorf("[storeCVEData] %v\n", err)
						continue
					}

					if changed {
						c.logger.Printf("Update CVE data to DB: %s\n", vuln.Cve.ID)

						if vuln.Cve.VulnStatus != "Received" {
							err = c.sqs.SendMessage(vuln.Cve.ID)
							if err != nil {
								c.logger.Errorf("[SendMessage] %v", err)
							} else {
								c.logger.Printf("Publish CVE update to SQS: %s", vuln.Cve.ID)
							}
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

			c.logger.Printf("Fetching CVEs from %s to %s (UTC) is completed\n", startDate.Format(time.RFC3339), endDate.Format(time.RFC3339))
			c.logger.Printf("Updated CVE : %d / %d\n", updateResults, totalResults)
		}
	}
}

func fetchCVEData(config common.NVDConfig, startDate, endDate time.Time, startIndex int) (*models.NVDResponse, error) {
	client := &http.Client{Timeout: 60 * time.Second}

	params := url.Values{}
	params.Add("pubStartDate", startDate.Format(time.RFC3339))
	params.Add("pubEndDate", endDate.Format(time.RFC3339))
	params.Add("startIndex", fmt.Sprintf("%d", startIndex))
	params.Add("resultsPerPage", "500")

	req, err := http.NewRequest("GET", config.APIUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("[NewRequest] %v", err)
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
		return nil, fmt.Errorf("[Response] %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[HTTP Status code] %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("[ReadAll] %v", err)
	}

	var nvdResp models.NVDResponse
	err = json.Unmarshal(body, &nvdResp)
	if err != nil {
		return nil, fmt.Errorf("[Unmarshal] %v", err)
	}

	return &nvdResp, nil
}

func storeCVEData(db common.DatabaseConnector, cve models.CVEData) (bool, error) {
	query := `
	WITH 
	changes AS (
		SELECT
		$1::VARCHAR(20) AS cve_id,
		$2::TIMESTAMP AS published_date,
		$3::TIMESTAMP AS last_modified_date,
		$4::TEXT AS vulnerability_status,
		$5::TEXT AS description,
		$6::VARCHAR(100) AS cvss_v3_vector,
		$7::REAL AS cvss_v3_base_score,
		$8::VARCHAR(20) AS cvss_v3_base_severity,
		$9::VARCHAR(255) AS cvss_v4_vector,
		$10::REAL AS cvss_v4_base_score,
		$11::VARCHAR(20) AS cvss_v4_base_severity,
		$12::TEXT[] AS affected_products,
		$13::TEXT[] AS reference_links,
		$14::TEXT[] AS cwe_ids
	),
	upsert AS (
		INSERT INTO cve_data (
			cve_id, published_date, last_modified_date, vulnerability_status, description,
			cvss_v3_vector, cvss_v3_base_score, cvss_v3_base_severity,
			cvss_v4_vector, cvss_v4_base_score, cvss_v4_base_severity,
			affected_products, reference_links, cwe_ids, updated_at
		) 
		SELECT *, CURRENT_TIMESTAMP
		FROM changes
		ON CONFLICT (cve_id) DO UPDATE SET
		published_date = EXCLUDED.published_date,
		last_modified_date = EXCLUDED.last_modified_date,
		vulnerability_status = EXCLUDED.vulnerability_status,
		description = EXCLUDED.description,
		cvss_v3_vector = EXCLUDED.cvss_v3_vector,
		cvss_v3_base_score = EXCLUDED.cvss_v3_base_score,
		cvss_v3_base_severity = EXCLUDED.cvss_v3_base_severity,
		cvss_v4_vector = EXCLUDED.cvss_v4_vector,
		cvss_v4_base_score = EXCLUDED.cvss_v4_base_score,
		cvss_v4_base_severity = EXCLUDED.cvss_v4_base_severity,
		affected_products = EXCLUDED.affected_products,
		reference_links = EXCLUDED.reference_links,
		cwe_ids = EXCLUDED.cwe_ids,
		updated_at = CASE
		WHEN (
			cve_data.published_date IS DISTINCT FROM EXCLUDED.published_date OR
			cve_data.last_modified_date IS DISTINCT FROM EXCLUDED.last_modified_date OR
			cve_data.vulnerability_status IS DISTINCT FROM EXCLUDED.vulnerability_status OR
			cve_data.description IS DISTINCT FROM EXCLUDED.description OR
			cve_data.cvss_v3_vector IS DISTINCT FROM EXCLUDED.cvss_v3_vector OR
			cve_data.cvss_v3_base_score IS DISTINCT FROM EXCLUDED.cvss_v3_base_score OR
			cve_data.cvss_v3_base_severity IS DISTINCT FROM EXCLUDED.cvss_v3_base_severity OR
			cve_data.cvss_v4_vector IS DISTINCT FROM EXCLUDED.cvss_v4_vector OR
			cve_data.cvss_v4_base_score IS DISTINCT FROM EXCLUDED.cvss_v4_base_score OR
			cve_data.cvss_v4_base_severity IS DISTINCT FROM EXCLUDED.cvss_v4_base_severity OR
			cve_data.affected_products IS DISTINCT FROM EXCLUDED.affected_products OR
			cve_data.reference_links IS DISTINCT FROM EXCLUDED.reference_links OR
			cve_data.cwe_ids IS DISTINCT FROM EXCLUDED.cwe_ids
		) THEN CURRENT_TIMESTAMP
		ELSE cve_data.updated_at
		END
		RETURNING 
		(xmax = 0) AS inserted,
		(updated_at = CURRENT_TIMESTAMP) AS updated
	)
	SELECT 
		(inserted OR updated) AS changed
	FROM upsert
	`

	var changed bool
	err := db.QueryRow(query,
		cve.ID, cve.Published.Time, cve.LastModified.Time, cve.VulnStatus, getDescription(cve),
		getCVSSV3Vector(cve), getCVSSV3BaseScore(cve), getCVSSV3BaseSeverity(cve),
		getCVSSV4Vector(cve), getCVSSV4BaseScore(cve), getCVSSV4BaseSeverity(cve),
		pq.Array(getAffectedProducts(cve)), pq.Array(getReferenceLinks(cve)), pq.Array(getCWEIDs(cve)),
	).Scan(&changed)

	if err != nil {
		return false, err
	}

	return changed, nil
}

func getDescription(cve models.CVEData) string {
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	return ""
}

func getCVSSV3Vector(cve models.CVEData) string {
	if len(cve.Metrics.CvssMetricV31) > 0 {
		return cve.Metrics.CvssMetricV31[0].CvssData.VectorString
	}
	return ""
}

func getCVSSV3BaseScore(cve models.CVEData) float64 {
	if len(cve.Metrics.CvssMetricV31) > 0 {
		return cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
	}
	return 0
}

func getCVSSV3BaseSeverity(cve models.CVEData) string {
	if len(cve.Metrics.CvssMetricV31) > 0 {
		return cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
	}
	return ""
}

func getCVSSV4Vector(cve models.CVEData) string {
	if len(cve.Metrics.CvssMetricV40) > 0 {
		return cve.Metrics.CvssMetricV40[0].CvssData.VectorString
	}
	return ""
}

func getCVSSV4BaseScore(cve models.CVEData) float64 {
	if len(cve.Metrics.CvssMetricV40) > 0 {
		return cve.Metrics.CvssMetricV40[0].CvssData.BaseScore
	}
	return 0
}

func getCVSSV4BaseSeverity(cve models.CVEData) string {
	if len(cve.Metrics.CvssMetricV40) > 0 {
		return cve.Metrics.CvssMetricV40[0].CvssData.BaseSeverity
	}
	return ""
}

func getAffectedProducts(cve models.CVEData) []string {
	var products []string
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			for _, cpe := range node.CpeMatch {
				products = append(products, cpe.Criteria)
			}
		}
	}
	return products
}

func getReferenceLinks(cve models.CVEData) []string {
	var links []string
	for _, ref := range cve.References {
		links = append(links, ref.URL)
	}
	return links
}

func getCWEIDs(cve models.CVEData) []string {
	var cweIDs []string
	for _, weakness := range cve.Weaknesses {
		for _, desc := range weakness.Description {
			cweIDs = append(cweIDs, desc.Value)
		}
	}
	return cweIDs
}
