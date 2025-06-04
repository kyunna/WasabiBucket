// Package models provides structures related to AI analysis results.
package models

// AIAnalysis captures structured results from LLM-based vulnerability analysis.
type AIAnalysis struct {
	AnalysisSummary   string   `json:"analysis_summary"`
	AffectedSystems   string   `json:"affected_systems"`
	AffectedProducts  []string `json:"affected_products"` // Stored using custom StringArray type
	VulnerabilityType string   `json:"vulnerability_type"`
	RiskLevel         int      `json:"risk_level"`
	Recommendation    string   `json:"recommendation"`
	TechnicalDetails  string   `json:"technical_details"`
}
