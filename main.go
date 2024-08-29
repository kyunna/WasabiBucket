package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/joho/godotenv"
	"github.com/lib/pq"
)

const (
	nvdAPIURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

var (
	logger *log.Logger
	apiKey string
	db     *sql.DB
)

type CustomTime struct {
	time.Time
}

func (ct *CustomTime) UnmarshalJSON(b []byte) error {
	s := string(b)
	s = s[1 : len(s)-1]
	t, err := time.Parse("2006-01-02T15:04:05.000", s)
	if err != nil {
		return err
	}
	ct.Time = t
	return nil
}

type NVDResponse struct {
	Vulnerabilities []struct {
		Cve CVEData `json:"cve"`
	} `json:"vulnerabilities"`
	ResultsPerPage int `json:"resultsPerPage"`
	StartIndex     int `json:"startIndex"`
	TotalResults   int `json:"totalResults"`
}

type CVEData struct {
	ID               string     `json:"id"`
	Published        CustomTime `json:"published"`
	LastModified     CustomTime `json:"lastModified"`
	VulnStatus       string     `json:"vulnStatus"`
	Descriptions     []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CvssMetricV31 []struct {
			CvssData CVSSData `json:"cvssData"`
		} `json:"cvssMetricV31"`
		CvssMetricV40 []struct {
			CvssData CVSSData `json:"cvssData"`
		} `json:"cvssMetricV40"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			CpeMatch []struct {
				Criteria string `json:"criteria"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Weaknesses []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
}

type CVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

func init() {
	if err := godotenv.Load(); err != nil {
		log.Printf("Error loading .env file: %v", err)
	}

	apiKey = os.Getenv("NVD_API_KEY")
	if apiKey == "" {
		log.Fatal("NVD_API_KEY not set in .env file")
	}

	// PostgreSQL 연결 설정
	dbHost := "wasabibucket.cdyakuqm2sfh.ap-northeast-2.rds.amazonaws.com"
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD") // .env 파일에서 비밀번호를 가져옵니다.
	dbName := os.Getenv("DB_NAME")
	dbPort := os.Getenv("DB_PORT") 

	connectionString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=require",
	dbHost, dbPort, dbUser, dbPassword, dbName)

	var err error
	db, err = sql.Open("postgres", connectionString)
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Error pinging the database: %v", err)
	}

	log.Println("Successfully connected to the database")
	
}

func main() {
	defer db.Close()

	setupLogger()

	// location, err := time.LoadLocation("Asia/Seoul")
	// if err != nil {
	// 	fmt.Printf("Error loading location: %v\n", err)
	// 	return
	// }

	// now := time.Now().In(location)
	// startDate := now.Add(-3 * time.Hour).Truncate(time.Hour)
	// endDate := now

	startDate, _ := time.Parse("2006-01-02T15:04:05.000", "2024-07-31T00:00:00.000")
	endDate,_ := time.Parse("2006-01-02T15:04:05.000", "2024-08-29T00:00:00.000")

	startDateGMT := startDate.UTC()
	endDateGMT := endDate.UTC()

	logger.Printf("Fetching CVEs from %s to %s (GMT)\n", startDateGMT.Format(time.RFC3339), endDateGMT.Format(time.RFC3339))
	fmt.Printf("Fetching CVEs from %s to %s (GMT)\n", startDateGMT.Format(time.RFC3339), endDateGMT.Format(time.RFC3339))

	startIndex := 0
	totalResults := 0

	for {
		resp, err := fetchCVEData(startDateGMT, endDateGMT, startIndex)
		if err != nil {
			logger.Printf("Error fetching CVE data: %v\n", err)
			return
		}

		for _, vuln := range resp.Vulnerabilities {
			printCVEInfo(vuln.Cve)
			err := insertCVEData(vuln.Cve)
			if err != nil {
				logger.Printf("Error inserting CVE data: %v\n", err)
			}
		}

		totalResults = resp.TotalResults
		startIndex += resp.ResultsPerPage

		if startIndex >= totalResults {
			break
		}

		time.Sleep(6 * time.Second)
	}

	logger.Printf("Total CVEs fetched: %d\n", totalResults)
}

func insertCVEData(cve CVEData) error {
	_, err := db.Exec(`
		INSERT INTO cve_data (
			cve_id, published_date, last_modified_date, vulnerability_status, description,
			cvss_v3_vector, cvss_v3_base_score, cvss_v3_base_severity,
			cvss_v4_vector, cvss_v4_base_score, cvss_v4_base_severity,
			affected_products, reference_links, cwe_ids
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
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
		cwe_ids = EXCLUDED.cwe_ids
		`,
		cve.ID,
		cve.Published.Time,
		cve.LastModified.Time,
		cve.VulnStatus,
		getDescription(cve),
		getCVSSV3Vector(cve),
		getCVSSV3BaseScore(cve),
		getCVSSV3BaseSeverity(cve),
		getCVSSV4Vector(cve),
		getCVSSV4BaseScore(cve),
		getCVSSV4BaseSeverity(cve),
		pq.Array(getAffectedProducts(cve)),
		pq.Array(getReferenceLinks(cve)),
		pq.Array(getCWEIDs(cve)),
	)

	return err
}

func getDescription(cve CVEData) string {
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	return ""
}

func getCVSSV3Vector(cve CVEData) string {
	if len(cve.Metrics.CvssMetricV31) > 0 {
		return cve.Metrics.CvssMetricV31[0].CvssData.VectorString
	}
	return ""
}

func getCVSSV3BaseScore(cve CVEData) float64 {
	if len(cve.Metrics.CvssMetricV31) > 0 {
		return cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
	}
	return 0
}

func getCVSSV3BaseSeverity(cve CVEData) string {
	if len(cve.Metrics.CvssMetricV31) > 0 {
		return cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
	}
	return ""
}

func getCVSSV4Vector(cve CVEData) string {
    if len(cve.Metrics.CvssMetricV40) > 0 {
        return cve.Metrics.CvssMetricV40[0].CvssData.VectorString
    }
    return ""
}

func getCVSSV4BaseScore(cve CVEData) float64 {
	if len(cve.Metrics.CvssMetricV40) > 0 {
		return cve.Metrics.CvssMetricV40[0].CvssData.BaseScore
	}
	return 0
}

func getCVSSV4BaseSeverity(cve CVEData) string {
	if len(cve.Metrics.CvssMetricV40) > 0 {
		return cve.Metrics.CvssMetricV40[0].CvssData.BaseSeverity
	}
	return ""
}

func getAffectedProducts(cve CVEData) []string {
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

func getReferenceLinks(cve CVEData) []string {
	var links []string
	for _, ref := range cve.References {
		links = append(links, ref.URL)
	}
	return links
}

func getCWEIDs(cve CVEData) []string {
	var cweIDs []string
	for _, weakness := range cve.Weaknesses {
		for _, desc := range weakness.Description {
			cweIDs = append(cweIDs, desc.Value)
		}
	}
	return cweIDs
}

func setupLogger() {
	logDir := filepath.Join(".", "log")
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		log.Fatalf("Error creating log directory: %v", err)
	}

	currentDate := time.Now().Format("2006-01-02")
	logFile, err := os.OpenFile(filepath.Join(logDir, currentDate+".log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}

	logger = log.New(logFile, "", log.Ldate|log.Ltime|log.Lshortfile)
}

func fetchCVEData(startDate, endDate time.Time, startIndex int) (*NVDResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	params := url.Values{}
	params.Add("pubStartDate", startDate.Format(time.RFC3339))
	params.Add("pubEndDate", endDate.Format(time.RFC3339))
	params.Add("startIndex", fmt.Sprintf("%d", startIndex))
	params.Add("resultsPerPage", "100")

	req, err := http.NewRequest("GET", nvdAPIURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("apiKey", apiKey)
	req.URL.RawQuery = params.Encode()

	logger.Printf("Attempting API request: %s\n", req.URL.String())

	var resp *http.Response
	for retries := 0; retries < 3; retries++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		logger.Printf("API request attempt %d failed: %v\n", retries+1, err)
		time.Sleep(time.Duration(retries+1) * time.Second)
	}

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Printf("API request failed with status code: %d\n", resp.StatusCode)
		return nil, fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var nvdResp NVDResponse
	err = json.Unmarshal(body, &nvdResp)
	if err != nil {
		return nil, err
	}

	logger.Printf("API request successful. Fetched %d CVEs.\n", len(nvdResp.Vulnerabilities))

	return &nvdResp, nil
}

func printCVEInfo(cve CVEData) {
	fmt.Printf("CVE ID: %s\n", cve.ID)
	fmt.Printf("Published: %s\n", cve.Published.Format(time.RFC3339))
	fmt.Printf("Last Modified: %s\n", cve.LastModified.Format(time.RFC3339))
	fmt.Printf("Vulnerability Status: %s\n", cve.VulnStatus)

	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			fmt.Printf("Description: %s\n", desc.Value)
			break
		}
	}

	if len(cve.Metrics.CvssMetricV31) > 0 {
		cvssData := cve.Metrics.CvssMetricV31[0].CvssData
		fmt.Printf("CVSS V3.1 Vector: %s\n", cvssData.VectorString)
		fmt.Printf("CVSS V3.1 Base Score: %.1f\n", cvssData.BaseScore)
		fmt.Printf("CVSS V3.1 Base Severity: %s\n", cvssData.BaseSeverity)
	}

	if len(cve.Metrics.CvssMetricV40) > 0 {
		cvssData := cve.Metrics.CvssMetricV40[0].CvssData
		fmt.Printf("CVSS V4.0 Vector: %s\n", cvssData.VectorString)
		fmt.Printf("CVSS V4.0 Base Score: %.1f\n", cvssData.BaseScore)
		fmt.Printf("CVSS V4.0 Base Severity: %s\n", cvssData.BaseSeverity)
	}

	fmt.Println("Affected Products (CPE):")
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			for _, cpe := range node.CpeMatch {
				fmt.Printf("  - %s\n", cpe.Criteria)
			}
		}
	}

	fmt.Println("Reference Links:")
	for _, ref := range cve.References {
		fmt.Printf("  - %s\n", ref.URL)
	}

	fmt.Println("CWE IDs:")
	for _, weakness := range cve.Weaknesses {
		for _, desc := range weakness.Description {
			fmt.Printf("  - %s\n", desc.Value)
		}
	}

	fmt.Println("----------------------------------------")
}
