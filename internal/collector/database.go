package collector

import (
	"github.com/lib/pq"
	"wasabibucket/internal/common"
	"wasabibucket/pkg/models"
)

func storeCVEData(db *common.Database, cve models.CVEData) (bool, error) {
	query := `
	WITH 
	changes AS (
		SELECT
		$1::VARCHAR(20) AS cve_id,
		$2::TIMESTAMP AS published_date,
		$3::TIMESTAMP AS last_modified_date,
		$4::TEXT AS vulnerability_status,
		$5::TEXT AS description,
		$6::VARCHAR(100) AS cvss_v3_vector,
		$7::REAL AS cvss_v3_base_score,
		$8::VARCHAR(20) AS cvss_v3_base_severity,
		$9::VARCHAR(255) AS cvss_v4_vector,
		$10::REAL AS cvss_v4_base_score,
		$11::VARCHAR(20) AS cvss_v4_base_severity,
		$12::TEXT[] AS affected_products,
		$13::TEXT[] AS reference_links,
		$14::TEXT[] AS cwe_ids
	),
	upsert AS (
		INSERT INTO cve_data (
			cve_id, published_date, last_modified_date, vulnerability_status, description,
			cvss_v3_vector, cvss_v3_base_score, cvss_v3_base_severity,
			cvss_v4_vector, cvss_v4_base_score, cvss_v4_base_severity,
			affected_products, reference_links, cwe_ids, updated_at
		) 
		SELECT *, CURRENT_TIMESTAMP
		FROM changes
		ON CONFLICT (cve_id) DO UPDATE SET
		published_date = EXCLUDED.published_date,
		last_modified_date = EXCLUDED.last_modified_date,
		vulnerability_status = EXCLUDED.vulnerability_status,
		description = EXCLUDED.description,
		cvss_v3_vector = EXCLUDED.cvss_v3_vector,
		cvss_v3_base_score = EXCLUDED.cvss_v3_base_score,
		cvss_v3_base_severity = EXCLUDED.cvss_v3_base_severity,
		cvss_v4_vector = EXCLUDED.cvss_v4_vector,
		cvss_v4_base_score = EXCLUDED.cvss_v4_base_score,
		cvss_v4_base_severity = EXCLUDED.cvss_v4_base_severity,
		affected_products = EXCLUDED.affected_products,
		reference_links = EXCLUDED.reference_links,
		cwe_ids = EXCLUDED.cwe_ids,
		updated_at = CASE
		WHEN (
			cve_data.published_date IS DISTINCT FROM EXCLUDED.published_date OR
			cve_data.last_modified_date IS DISTINCT FROM EXCLUDED.last_modified_date OR
			cve_data.vulnerability_status IS DISTINCT FROM EXCLUDED.vulnerability_status OR
			cve_data.description IS DISTINCT FROM EXCLUDED.description OR
			cve_data.cvss_v3_vector IS DISTINCT FROM EXCLUDED.cvss_v3_vector OR
			cve_data.cvss_v3_base_score IS DISTINCT FROM EXCLUDED.cvss_v3_base_score OR
			cve_data.cvss_v3_base_severity IS DISTINCT FROM EXCLUDED.cvss_v3_base_severity OR
			cve_data.cvss_v4_vector IS DISTINCT FROM EXCLUDED.cvss_v4_vector OR
			cve_data.cvss_v4_base_score IS DISTINCT FROM EXCLUDED.cvss_v4_base_score OR
			cve_data.cvss_v4_base_severity IS DISTINCT FROM EXCLUDED.cvss_v4_base_severity OR
			cve_data.affected_products IS DISTINCT FROM EXCLUDED.affected_products OR
			cve_data.reference_links IS DISTINCT FROM EXCLUDED.reference_links OR
			cve_data.cwe_ids IS DISTINCT FROM EXCLUDED.cwe_ids
		) THEN CURRENT_TIMESTAMP
		ELSE cve_data.updated_at
		END
		RETURNING 
		(xmax = 0) AS inserted,
		(updated_at = CURRENT_TIMESTAMP) AS updated
	)
	SELECT 
	(inserted OR updated) AS changed
	FROM upsert
	`

	var changed bool
	err := db.QueryRow(query,
	cve.ID, cve.Published.Time, cve.LastModified.Time, cve.VulnStatus, getDescription(cve),
	getCVSSV3Vector(cve), getCVSSV3BaseScore(cve), getCVSSV3BaseSeverity(cve),
	getCVSSV4Vector(cve), getCVSSV4BaseScore(cve), getCVSSV4BaseSeverity(cve),
	pq.Array(getAffectedProducts(cve)), pq.Array(getReferenceLinks(cve)), pq.Array(getCWEIDs(cve)),
	).Scan(&changed)

	if err != nil {
		return false, err
	}

	return changed, nil
}

func getDescription(cve models.CVEData) string {
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	return ""
}

func getCVSSV3Vector(cve models.CVEData) string {
	if len(cve.Metrics.CvssMetricV31) > 0 {
		return cve.Metrics.CvssMetricV31[0].CvssData.VectorString
	}
	return ""
}

func getCVSSV3BaseScore(cve models.CVEData) float64 {
	if len(cve.Metrics.CvssMetricV31) > 0 {
		return cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
	}
	return 0
}

func getCVSSV3BaseSeverity(cve models.CVEData) string {
	if len(cve.Metrics.CvssMetricV31) > 0 {
		return cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
	}
	return ""
}

func getCVSSV4Vector(cve models.CVEData) string {
	if len(cve.Metrics.CvssMetricV40) > 0 {
		return cve.Metrics.CvssMetricV40[0].CvssData.VectorString
	}
	return ""
}

func getCVSSV4BaseScore(cve models.CVEData) float64 {
	if len(cve.Metrics.CvssMetricV40) > 0 {
		return cve.Metrics.CvssMetricV40[0].CvssData.BaseScore
	}
	return 0
}

func getCVSSV4BaseSeverity(cve models.CVEData) string {
	if len(cve.Metrics.CvssMetricV40) > 0 {
		return cve.Metrics.CvssMetricV40[0].CvssData.BaseSeverity
	}
	return ""
}

func getAffectedProducts(cve models.CVEData) []string {
	var products []string
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			for _, cpe := range node.CpeMatch {
				products = append(products, cpe.Criteria)
			}
		}
	}
	return products
}

func getReferenceLinks(cve models.CVEData) []string {
	var links []string
	for _, ref := range cve.References {
		links = append(links, ref.URL)
	}
	return links
}

func getCWEIDs(cve models.CVEData) []string {
	var cweIDs []string
	for _, weakness := range cve.Weaknesses {
		for _, desc := range weakness.Description {
			cweIDs = append(cweIDs, desc.Value)
		}
	}
	return cweIDs
}
