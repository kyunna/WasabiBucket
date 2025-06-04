package analyzer

import (
	"fmt"

	"wasabibucket/internal/common"
	"wasabibucket/internal/models"
)

func storePoCData(db common.DatabaseConnector, grouped []models.GroupedPoC) error {
	for _, g := range grouped {
		var pocInfoID int
		queryInfo := `
		INSERT INTO poc_info (cve_id, source, url, author, language, verified, description)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (cve_id, source, url) DO UPDATE SET
			author = EXCLUDED.author,
			language = EXCLUDED.language,
			verified = EXCLUDED.verified,
			description = EXCLUDED.description,
			updated_at = CASE
				WHEN poc_info.author IS DISTINCT FROM EXCLUDED.author OR
					poc_info.language IS DISTINCT FROM EXCLUDED.language OR
					poc_info.verified IS DISTINCT FROM EXCLUDED.verified OR
					poc_info.description IS DISTINCT FROM EXCLUDED.description
				THEN CURRENT_TIMESTAMP ELSE poc_info.updated_at END
		RETURNING id`

		err := db.QueryRow(queryInfo, g.Info.CVEID, g.Info.Source, g.Info.URL, g.Info.Author, g.Info.Language, g.Info.Verified, g.Info.Description).Scan(&pocInfoID)
		if err != nil {
			return fmt.Errorf("failed to insert poc_info: %v", err)
		}

		for _, f := range g.Files {
			_, err := db.Exec(`
			INSERT INTO poc_file (poc_info_id, path, file_url, file_ext)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (poc_info_id, file_url) DO NOTHING
			`, pocInfoID, f.Path, f.FileURL, f.FileExt)
			if err != nil {
				return fmt.Errorf("failed to insert poc_file: %v", err)
			}
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
