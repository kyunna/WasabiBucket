package models

type AIAnalysis struct {
	AnalysisSummary   string   `json:"analysis_summary"`
	AffectedSystems   string   `json:"affected_systems"`
	AffectedProducts  []string `json:"affected_products"` // Stored using custom StringArray type
	VulnerabilityType string   `json:"vulnerability_type"`
	RiskLevel         int      `json:"risk_level"`
	Recommendation    string   `json:"recommendation"`
	TechnicalDetails  string   `json:"technical_details"`
}
