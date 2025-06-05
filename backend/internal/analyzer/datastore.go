package analyzer

import (
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

func storeAnalysisResult(db common.DatabaseConnector, cveID string, analysis *models.AIAnalysis) error {
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
