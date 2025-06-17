package models

// NVD model: Metadata and detailed information of CVE
type CVEData struct {
	ID           string     `json:"id"`
	Published    CustomTime `json:"published"`
	LastModified CustomTime `json:"lastModified"`
	VulnStatus   string     `json:"vulnStatus"`
	Descriptions []struct {
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

type NVDResponse struct {
	Vulnerabilities []struct {
		Cve CVEData `json:"cve"`
	} `json:"vulnerabilities"`
	ResultsPerPage int `json:"resultsPerPage"`
	StartIndex     int `json:"startIndex"`
	TotalResults   int `json:"totalResults"`
}

// PostgreSQL model: Stores CVE data in the database
type CVEInfo struct {
	ID                 string
	Description        string
	CvssV3Vector       string
	CvssV3BaseScore    float64
	CvssV3BaseSeverity string
	CvssV4Vector       string
	CvssV4BaseScore    float64
	CvssV4BaseSeverity string
	AffectedProducts   []string
	CWEIDs             []string
}
