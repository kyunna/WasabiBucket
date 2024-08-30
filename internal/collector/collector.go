package collector

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "time"

    "wasabibucket/internal/common"
    "wasabibucket/pkg/models"
)

const nvdAPIURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

func fetchCVEData(config *common.Config, startDate, endDate time.Time, startIndex int) (*models.NVDResponse, error) {
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

    req.Header.Add("apiKey", config.NVDAPIKey)
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

func CollectCVEData(config *common.Config, db *common.Database, logger *common.Logger, startDate, endDate time.Time) error {
    startIndex := 0
    totalResults := 0

    for {
        resp, err := fetchCVEData(config, startDate, endDate, startIndex)
        if err != nil {
            return fmt.Errorf("error fetching CVE data: %v", err)
        }

        for _, vuln := range resp.Vulnerabilities {
            err := storeCVEData(db, vuln.Cve)
            if err != nil {
                logger.Printf("Error storing CVE data: %v\n", err)
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
    return nil
}