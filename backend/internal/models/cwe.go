package models

// Mitre models: Metadata and detailed information of CWE
type CWEMeta struct {
	Type string `json:"Type"`
	ID   string `json:"ID"`
}

type CWEData struct {
	ID                  string `json:"ID"`
	Name                string `json:"Name"`
	Description         string `json:"Description"`
	ExtendedDescription string `json:"ExtendedDescription"`
	LikelihoodOfExploit string `json:"LikelihoodOfExploit"`
	CommonConsequences  []CommonConsequence `json:"CommonConsequences"` // 특정 CWE(취약점 유형)가 악용되었을 때 발생할 수 있는 결과(영향, 피해 범주)
}

type CommonConsequence struct {
	Scope  []string `json:"Scope"`
	Impact []string `json:"Impact"`
	Note   string   `json:"Note,omitempty"`
}

// PostgreSQL model: Stores CWE summary data in the database
type CWEInfo struct {
  CWEID      string `json:"cwe_id"`
  SummaryEn  string `json:"summary_en"`
  SummaryKo  string `json:"summary_ko"`
  SourceURL  string `json:"source_url"`
}
