package analyzer

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"wasabibucket/internal/common"
	"wasabibucket/internal/models"
)

func getCWEInfo(db common.DatabaseConnector, cweID string) (*models.CWEInfo, error) {
	query := `
		SELECT cwe_id, summary_en, summary_ko, source_url
		FROM cwe_info
		WHERE cwe_id = $1
	`

	row := db.QueryRow(query, cweID)

	var info models.CWEInfo
	err := row.Scan(
		&info.CWEID,
		&info.SummaryEn,
		&info.CWEID,
		&info.SourceURL,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to query CWE infomation: %w", err)
	}

	return &info, nil
}

func fetchCWEInfo(cweID string) (*models.CWEData, error) {
	id := extractID(cweID)

	// Step 1: Determine CWE type
	metaURL := fmt.Sprintf("https://cwe-api.mitre.org/api/v1/cwe/%s", id)
	resp, err := http.Get(metaURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CWE meta info: %w", err)
	}
	defer resp.Body.Close()

	metaBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read meta response body: %w", err)
	}

	var metas []models.CWEMeta
	if err := json.Unmarshal(metaBody, &metas); err != nil {
		return nil, fmt.Errorf("failed to parse CWE meta info: %w", err)
	}
	if len(metas) == 0 || !isWeaknessType(metas[0].Type) {
		return nil, fmt.Errorf("CWE-%s is not a weakness type (type: %s)", id, metas[0].Type)
	}

	// Step 2: Fetch detailed weakness info
	detailURL := fmt.Sprintf("https://cwe-api.mitre.org/api/v1/cwe/weakness/%s", id)
	detailResp, err := http.Get(detailURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CWE detail info: %w", err)
	}
	defer detailResp.Body.Close()

	detailBody, err := io.ReadAll(detailResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read detail response body: %w", err)
	}

	var wrapper struct {
		Weaknesses []models.CWEData `json:"Weaknesses"`
	}
	if err := json.Unmarshal(detailBody, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse CWE detail info: %w", err)
	}
	if len(wrapper.Weaknesses) == 0 {
		return nil, fmt.Errorf("no detailed info found for CWE-%s", id)
	}

	return &wrapper.Weaknesses[0], nil
}

func isWeaknessType(t string) bool {
	// https://cwe.mitre.org/documents/cwe_usage/common_terms_cheatsheet.html
	// Pillar Weakness, Class Weakness, Base Weakness, Variant Weakness ..
	return strings.Contains(t, "weakness")
}

func extractID(input string) string {
	return strings.TrimPrefix(strings.ToUpper(input), "CWE-")
}
