package analyzer

import (
	"fmt"
	"time"
)

func (a *Analyzer) storeAnalysisResult(cveID, analysis string) error {
	query := `
		INSERT INTO ai_analysis (cve_id, analysis_summary, created_at, updated_at)
		VALUES ($1, $2, $3, $3)
		ON CONFLICT (cve_id) DO UPDATE SET
			analysis_summary = EXCLUDED.analysis_summary,
			updated_at = EXCLUDED.updated_at
	`
	_, err := a.db.Exec(query, cveID, analysis, time.Now())
	if err != nil {
		return fmt.Errorf("Failed to store analysis result: %w", err)
	}
	return nil
}
