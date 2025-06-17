package analyzer

import (
	"database/sql"
	"fmt"

	"wasabibucket/internal/common"
	"wasabibucket/internal/models"

	"github.com/lib/pq"
)

func getCVEInfo(db common.DatabaseConnector, cveID string) (*models.CVEInfo, error) {
	var affectedProducts, cweIDs pq.StringArray
	info := &models.CVEInfo{ID: cveID}

	query := `
		SELECT 
		cve_id, 
		description, 
		cvss_v3_vector, 
		cvss_v3_base_score, 
		cvss_v3_base_severity,
		cvss_v4_vector, 
		cvss_v4_base_score, 
		cvss_v4_base_severity,
		affected_products,
		cwe_ids
		FROM cve_data 
		WHERE cve_id = $1
		`
	err := db.QueryRow(query, cveID).Scan(
		&info.ID,
		&info.Description,
		&info.CvssV3Vector,
		&info.CvssV3BaseScore,
		&info.CvssV3BaseSeverity,
		&info.CvssV4Vector,
		&info.CvssV4BaseScore,
		&info.CvssV4BaseSeverity,
		&affectedProducts,
		&cweIDs,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("not found in database")
		}
		return nil, fmt.Errorf("failed to query CVE infomation: %w", err)
	}

	info.AffectedProducts = []string(affectedProducts)
	info.CWEIDs = []string(cweIDs)

	return info, nil
}
