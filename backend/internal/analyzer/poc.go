package analyzer

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"strconv"
	"time"

	"wasabibucket/internal/models"
)

func fetchExploitDBPoC(cveID, baseDir string) ([]models.PoCData, error) {
	csvPath := filepath.Join(baseDir, "files_exploits.csv")
	file, err := os.Open(csvPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open CSV: %v", err)
	}
	defer file.Close()

	r := csv.NewReader(file)
	r.LazyQuotes = true
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV: %v", err)
	}

	var results []models.PoCData

	for idx, row := range records {
		if idx == 0 || len(row) < 12 {
			continue // skip header or malformed row
		}

		cveList := strings.Split(row[11], ";")
		matched := false
		for _, code := range cveList {
			if strings.TrimSpace(code) == cveID {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		edbID := row[0]
		filePath := row[1]

		exploitFilePath := filepath.Join(baseDir, filePath)
		contentBytes, err := os.ReadFile(exploitFilePath)
		content := ""
		if err != nil {
			content = "[RETRY_REQUIRED: failed to read local file]"
		} else {
			content = string(contentBytes)
		}

		rawURL := "https://gitlab.com/exploit-database/exploitdb/-/raw/main/" + filePath
		repoURL := "https://www.exploit-db.com/exploits/" + edbID

		results = append(results, models.PoCData{
			CVEID:   cveID,
			Source:  "Exploit-DB",
			RepoURL: repoURL,
			FileURL: rawURL,
			Content: content,
		})
	}

	return results, nil
}

func fetchGitHubPoC(cveID, token string) ([]models.PoCData, error) {
	maxFiles := 10
	fileCount := 0

	allowedExts := map[string]bool{
		".py": true, ".rb": true, ".sh": true, ".yaml": true,
		".yml": true, ".go": true, ".c": true, ".cpp": true, ".php": true,
	}

	var results []models.PoCData
	searchURL := fmt.Sprintf("https://api.github.com/search/code?q=%s+in:file", url.QueryEscape(cveID))

	for searchURL != "" && fileCount < maxFiles {
		req, err := http.NewRequest("GET", searchURL, nil)
		if err != nil {
			return results, fmt.Errorf("request create error: %w", err)
		}
		req.Header.Set("Authorization", "token "+token)
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return results, fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()

		// Check rate limit 
		if throttle, wait := shouldThrottle(resp.Header); throttle {
			time.Sleep(wait)
			continue
		}

		// Parse result
		var parsed models.GitHubSearchResponse
		body, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(body, &parsed); err != nil {
			return results, fmt.Errorf("json parse failed: %w", err)
		}

		var result models.GitHubSearchResponse
		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Printf("Unmarshal error: %v\n", err)
			break
		}

		for _, item := range parsed.Items {
			if fileCount >= maxFiles {
				break
			}

			if !allowedExts[filepath.Ext(item.Path)] {
				continue
			}

			// fetch raw content
			content, err := fetchGitHubFileContent(item, token)
			if err != nil || content == "" {
				continue
			}

			p := models.PoCData{
				CVEID:   cveID,
				Source:  "GitHub",
				RepoURL: item.Repository.HTMLURL,
				FileURL: item.HTMLURL,
				Content: content,
			}
			results = append(results, p)
			fileCount++
		}

		searchURL = extractNextURL(resp.Header.Get("Link"))
	}

	return results, nil
}

func extractNextURL(linkHeader string) string {
	parts := strings.Split(linkHeader, ",")
	for _, part := range parts {
		if strings.Contains(part, `rel="next"`) {
			start := strings.Index(part, "<") + 1
			end := strings.Index(part, ">")
			if start > 0 && end > start {
				return part[start:end]
			}
		}
	}
	return ""
}

func shouldThrottle(headers http.Header) (bool, time.Duration) {
	remaining, err := strconv.Atoi(headers.Get("X-Ratelimit-Remaining"))

	if err != nil || remaining <= 1 {
		reset, err := strconv.ParseInt(headers.Get("X-Ratelimit-Reset"), 10, 64)
		if err != nil {
			return true, 30 * time.Second
		}
		return true, time.Until(time.Unix(reset, 0))
	}
	return false, 0
}

func fetchGitHubFileContent(item models.GitHubSearchItem, token string) (string, error) {
	req, err := http.NewRequest("GET", item.URL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request for content URL: %w", err)
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	// fmt.Printf("%s\n",resp.Header.Get("X-Ratelimit-Remaining"))
	if resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-Ratelimit-Remaining") == "0" {
		return "[RETRY_REQUIRED: rate limit exceeded", nil
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata request failed: status %d", resp.StatusCode)
	}

	// Parse JSON for download_url
	var meta struct {
		DownloadURL string `json:"download_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return "", fmt.Errorf("failed to parse metadata: %w", err)
	}
	if meta.DownloadURL == "" {
		return "", fmt.Errorf("download_url not found")
	}

	// Now fetch raw content
	rawResp, err := http.Get(meta.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch raw content: %w", err)
	}
	defer rawResp.Body.Close()

	if rawResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("raw content request failed: status %d", rawResp.StatusCode)
	}

	body, err := io.ReadAll(rawResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read raw content: %w", err)
	}

	return string(body), nil
}
