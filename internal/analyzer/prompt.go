package analyzer

import (
	"fmt"
	"strings"
	"wasabibucket/internal/common"
	"wasabibucket/pkg/models"

	"github.com/lib/pq"
)

func generatePrompt(db common.DatabaseConnector, cveID string) (string, error) {
	var cve models.CVEResponse
	var affectedProducts, cweIDs pq.StringArray

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
		&cve.ID,
		&cve.Description,
		&cve.CvssV3Vector,
		&cve.CvssV3BaseScore,
		&cve.CvssV3BaseSeverity,
		&cve.CvssV4Vector,
		&cve.CvssV4BaseScore,
		&cve.CvssV4BaseSeverity,
		&affectedProducts,
		&cweIDs,
	)
	if err != nil {
		return "", err
	}
	cve.AffectedProducts = []string(affectedProducts)
	cve.CWEIDs = []string(cweIDs)

	var cvssInfo string
	if cve.CvssV3Vector != "" || cve.CvssV3BaseScore > 0 {
		cvssInfo = fmt.Sprintf(`
		CVSS V3 Vector: %s
		CVSS V3 Score: %.1f
		CVSS V3 Severity: %s`, cve.CvssV3Vector, cve.CvssV3BaseScore, cve.CvssV3BaseSeverity)
	} else if cve.CvssV4Vector != "" || cve.CvssV4BaseScore > 0 {
		cvssInfo = fmt.Sprintf(`
		CVSS V4 Vector: %s
		CVSS V4 Score: %.1f
		CVSS V4 Severity: %s`, cve.CvssV4Vector, cve.CvssV4BaseScore, cve.CvssV4BaseSeverity)
	} else {
		cvssInfo = "No CVSS information available"
	}

	var affectedProductsInfo string
	if len(cve.AffectedProducts) > 0 {
		affectedProductsInfo = fmt.Sprintf("Affected Products: %s", strings.Join(cve.AffectedProducts, ", "))
	} else {
		affectedProductsInfo = "No affected products information available"
	}

	prompt := fmt.Sprintf(`
		You are a cybersecurity expert. Based on the provided information about %s, give a concise assessment (maximum 5 sentences) of this vulnerability. Consider:
		1. The risk level based on CVSS score and severity
		2. Potential impacts on affected products/systems
		3. Notable characteristics or implications
		4. Brief mitigation recommendations, if applicable
		Ensure your response is comprehensive yet concise, integrating all relevant details from the provided information.

		Description: %s

		%s
		
		Affected Products: %s
		CWE IDs: %s

		Your response should be in Korean.
	`,
		cve.ID,
		cve.Description,
		cvssInfo,
		affectedProductsInfo,
		strings.Join(cve.CWEIDs, ", "),
	)

	return prompt, nil
}
