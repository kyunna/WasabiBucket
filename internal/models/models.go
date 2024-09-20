package models

import (
	"time"
	"encoding/json"
	"database/sql/driver"
	_ "github.com/lib/pq"
)

type CustomTime struct {
	time.Time
}

func (ct *CustomTime) UnmarshalJSON(b []byte) error {
	s := string(b)
	s = s[1 : len(s)-1]
	t, err := time.Parse("2006-01-02T15:04:05.000", s)
	if err != nil {
		return err
	}
	ct.Time = t
	return nil
}

type NVDResponse struct {
	Vulnerabilities []struct {
		Cve CVEData `json:"cve"`
	} `json:"vulnerabilities"`
	ResultsPerPage int `json:"resultsPerPage"`
	StartIndex     int `json:"startIndex"`
	TotalResults   int `json:"totalResults"`
}

type CVEResponse struct {
	ID               string 
	Description      string
	CvssV3Vector     string
	CvssV3BaseScore  float64 
	CvssV3BaseSeverity   string
	CvssV4Vector     string
	CvssV4BaseScore  float64
	CvssV4BaseSeverity   string
	AffectedProducts []string
	CWEIDs           []string
}

type CVEData struct {
	ID               string     `json:"id"`
	Published        CustomTime `json:"published"`
	LastModified     CustomTime `json:"lastModified"`
	VulnStatus       string     `json:"vulnStatus"`
	Descriptions     []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CvssMetricV31 []struct {
			CvssData CVSSData `json:"cvssData"`
		} `json:"cvssMetricV31"`
		CvssMetricV40 []struct {
			CvssData CVSSData `json:"cvssData"`
		} `json:"cvssMetricV40"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			CpeMatch []struct {
				Criteria string `json:"criteria"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Weaknesses []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
}

type CVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type AIAnalysis struct {
	AnalysisSummary   string   `json:"analysis_summary"`
	AffectedSystems   string   `json:"affected_systems"`
	AffectedProducts  []string `json:"affected_products"`
	VulnerabilityType string   `json:"vulnerability_type"`
	PotentialImpact   string   `json:"potential_impact"`
	RiskLevel         int      `json:"risk_level"`
	Recommendation    string   `json:"recommendation"`
}

// StringArray는 문자열 배열을 PostgreSQL의 text[]로 저장하기 위한 타입입니다.
type StringArray []string

func (a StringArray) Value() (driver.Value, error) {
	return json.Marshal(a)
}

func (a *StringArray) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), &a)
	}
	return json.Unmarshal(b, &a)
}
