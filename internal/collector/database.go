// internal/collector/database.go

package collector

import (
    "github.com/lib/pq"
    "wasabibucket/internal/common"
    "wasabibucket/pkg/models"
)

func storeCVEData(db *common.Database, cve models.CVEData) error {
    _, err := db.Exec(`
        INSERT INTO cve_data (
            cve_id, published_date, last_modified_date, vulnerability_status, description,
            cvss_v3_vector, cvss_v3_base_score, cvss_v3_base_severity,
            cvss_v4_vector, cvss_v4_base_score, cvss_v4_base_severity,
            affected_products, reference_links, cwe_ids
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
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
        cwe_ids = EXCLUDED.cwe_ids
    `,
        cve.ID,
        cve.Published.Time,
        cve.LastModified.Time,
        cve.VulnStatus,
        getDescription(cve),
        getCVSSV3Vector(cve),
        getCVSSV3BaseScore(cve),
        getCVSSV3BaseSeverity(cve),
        getCVSSV4Vector(cve),
        getCVSSV4BaseScore(cve),
        getCVSSV4BaseSeverity(cve),
        pq.Array(getAffectedProducts(cve)),
        pq.Array(getReferenceLinks(cve)),
        pq.Array(getCWEIDs(cve)),
    )

    return err
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
