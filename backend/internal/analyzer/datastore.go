package analyzer

import (
	"encoding/json"
	"fmt"

	"wasabibucket/internal/common"
	"wasabibucket/internal/models"
)

func storePoCData(db common.DatabaseConnector, pocData []models.PoCData) error {
	for _, p := range pocData {
		_, err := db.Exec(`
		INSERT INTO poc_data (cve_id, source, repo_url, file_url, content)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (file_url) DO NOTHING
		`, p.CVEID, p.Source, p.RepoURL, p.FileURL, p.Content)
		if err != nil {
			return fmt.Errorf("failed to insert PoCData for %s: %w", p.FileURL, err)
		}
	}
	return nil
}

func storeCWEData(db common.DatabaseConnector, data *models.CWEData) error {
	if data == nil {
		return fmt.Errorf("CWEData is nil")
	}

	query := `
		INSERT INTO cwe_data (
			cwe_id,
			name,
			description,
			extended_description,
			likelihood,
			common_consequences,
			updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
		ON CONFLICT (cwe_id) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			extended_description = EXCLUDED.extended_description,
			likelihood = EXCLUDED.likelihood,
			common_consequences = EXCLUDED.common_consequences,
			updated_at = CURRENT_TIMESTAMP
	`

	commonConsequencesJSON, err := json.Marshal(data.CommonConsequences)
	if err != nil {
		return fmt.Errorf("failed to marshal CommonConsequences: %w", err)
	}

	_, err = db.Exec(
		query,
		fmt.Sprintf("CWE-%s", data.ID),
		data.Name,
		data.Description,
		data.ExtendedDescription,
		data.LikelihoodOfExploit,
		commonConsequencesJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to store CWE data: %w", err)
	}

	return nil
}

func storeCWEInfo(db common.DatabaseConnector, info *models.CWEInfo) error {
	if info == nil {
		return fmt.Errorf("CWEInfo is nil")
	}

	query := `
			INSERT INTO cwe_info (
			cwe_id,
			summary_en,
			summary_ko,
			source_url,
			updated_at
		)
		VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
		ON CONFLICT (cwe_id) DO UPDATE SET
			summary_en = EXCLUDED.summary_en,
			summary_ko = EXCLUDED.summary_ko,
			source_url = EXCLUDED.source_url,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := db.Exec(query, info.CWEID, info.SummaryEn, info.SummaryKo, info.SourceURL)
	if err != nil {
		return fmt.Errorf("failed to store CWE info: %w", err)
	}
	return nil
}

func storeAnalysisResult(db common.DatabaseConnector, cveID string, analysis *models.CVEInfo) error {
	query := `
        INSERT INTO analysis_data (
            cve_id, analysis_summary, affected_systems, affected_products, 
            vulnerability_type, risk_level, recommendation, 
            technical_details, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT (cve_id) DO UPDATE SET
            analysis_summary = EXCLUDED.analysis_summary,
            affected_systems = EXCLUDED.affected_systems,
            affected_products = EXCLUDED.affected_products,
            vulnerability_type = EXCLUDED.vulnerability_type,
            risk_level = EXCLUDED.risk_level,
            recommendation = EXCLUDED.recommendation,
            technical_details = EXCLUDED.technical_details,
            updated_at = CURRENT_TIMESTAMP
    `
	_, err := db.Exec(query, cveID, analysis.AnalysisSummary, analysis.AffectedSystems,
		models.StringArray(analysis.AffectedProducts), analysis.VulnerabilityType,
		analysis.RiskLevel, analysis.Recommendation, analysis.TechnicalDetails)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	return nil
}
