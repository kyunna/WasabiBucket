package models

import "time"

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
