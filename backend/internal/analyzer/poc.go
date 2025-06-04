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

	"wasabibucket/internal/models"
)

func cleanExt(ext string) string {
	ext = strings.ToLower(ext)
	if len(ext) > 10 || strings.ContainsAny(ext, "%/:?=&") {
		return "unknown"
	}
	if ext == "" {
		return "none"
	}
	return ext
}

func mapLanguage(ext string) string {
	switch ext {
	case ".py":
		return "Python"
	case ".rb":
		return "Ruby"
	case ".c":
		return "C"
	case ".cpp":
		return "C++"
	case ".php":
		return "PHP"
	case ".sh":
		return "Shell"
	case ".pl":
		return "Perl"
	default:
		return strings.TrimPrefix(ext, ".")
	}
}

func fetchExploitDBPoC(cveID, baseDir string) ([]models.GroupedPoC, error) {
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

	var grouped []models.GroupedPoC
	for idx, row := range records {
		if idx == 0 || len(row) < 12 {
			continue
		}

		codes := strings.Split(row[11], ";")
		found := false
		for _, code := range codes {
			if strings.TrimSpace(code) == cveID {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		edbID := row[0]
		filePath := row[1]
		description := row[2]
		author := row[4]
		verified := row[9] == "1"
		fileExt := cleanExt(filepath.Ext(filePath))
		language := mapLanguage(fileExt)
		fileURL := "https://gitlab.com/exploit-database/exploitdb/-/raw/main/" + filePath
		url := "https://www.exploit-db.com/exploits/" + edbID

		info := models.PoCInfo{
			CVEID:       cveID,
			Source:      "Exploit-DB",
			URL:         url,
			Author:      author,
			Language:    language,
			Verified:    verified,
			Description: description,
		}
		file := models.PoCFile{
			Path:    filePath,
			FileURL: fileURL,
			FileExt: fileExt,
		}
		grouped = append(grouped, models.GroupedPoC{Info: info, Files: []models.PoCFile{file}})
	}
	return grouped, nil
}

func buildDescription(files []models.PoCFile, repo string) string {
	repoLower := strings.ToLower(repo)
	if strings.Contains(repoLower, "metasploit") {
		return "Metasploit exploit module for CVE PoC."
	}
	for _, f := range files {
		path := strings.ToLower(f.Path)
		if strings.Contains(path, "nuclei") || strings.HasSuffix(path, ".yaml") {
			return "Nuclei detection template."
		}
		if strings.HasSuffix(path, ".py") || strings.HasSuffix(path, ".rb") {
			return "Exploit PoC script."
		}
		if strings.Contains(path, "patch") {
			return "Unofficial patch or mitigation for CVE."
		}
	}
	return "PoC repository for CVE."
}

func fetchGitHubPoC(cveID, token string) ([]models.GitHubSearchItem, error) {
	query := url.QueryEscape(cveID + " in:file")
	baseURL := "https://api.github.com/search/code?q=" + query

	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result models.GitHubSearchResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result.Items, nil
}

func fetchRepoMetadata(repoFullName, token string) (string, string) {
	url := fmt.Sprintf("https://api.github.com/repos/%s", repoFullName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", ""
	}

	var meta models.RepoMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", ""
	}

	return meta.Language, meta.Description
}

func buildGroupedPoC(cveID string, items []models.GitHubSearchItem, token string) []models.GroupedPoC {
	groupMap := make(map[string][]models.PoCFile)
	repoMeta := make(map[string]struct {
		author   string
		fullName string
	})

	for _, item := range items {
		repoURL := item.Repository.HTMLURL
		repoMeta[repoURL] = struct {
			author   string
			fullName string
		}{item.Repository.Owner.Login, item.Repository.FullName}
		file := models.PoCFile{
			Path:    item.Path,
			FileURL: item.HTMLURL,
			FileExt: cleanExt(filepath.Ext(item.Path)),
		}
		groupMap[repoURL] = append(groupMap[repoURL], file)
	}

	var grouped []models.GroupedPoC
	for repoURL, files := range groupMap {
		author := repoMeta[repoURL].author
		repoFullName := repoMeta[repoURL].fullName
		language, description := fetchRepoMetadata(repoFullName, token)
		info := models.PoCInfo{
			CVEID:       cveID,
			Source:      "GitHub",
			URL:         repoURL,
			Author:      author,
			Language:    language,
			Verified:    false,
			Description: description,
		}
		grouped = append(grouped, models.GroupedPoC{Info: info, Files: files})
	}
	return grouped
}
