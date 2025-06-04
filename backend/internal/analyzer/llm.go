package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"wasabibucket/internal/common"
	"wasabibucket/internal/models"

	"github.com/lib/pq"
	"github.com/sashabaranov/go-openai"
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
	As a cybersecurity expert, analyze vulnerability %s based on the provided information. Respond in JSON format:

	{
	"analysis_summary": "Comprehensive analysis considering CVSS score, affected systems, and vulnerability type. (Max 5 sentences)",
	"affected_systems": "Brief description of impacted systems/software based on the CVE description (e.g., 'Linux kernel-based systems', 'WordPress plugin WPFactory Helper', 'Draytek Vigor 3910 router')",
	"affected_products": ["List", "of", "specific", "affected", "product", "names", "based", "on", "CPE", "information"],
	"vulnerability_type": "Category or type of vulnerability in English",
	"risk_level": 0, // 0: Low, 1: Medium, 2: High, based on CVSS score and severity
	"recommendation": "Specific actions to mitigate or address the vulnerability (2-3 sentences)",
	"technical_details": "Technical specifics, attack vectors, and potential impact if exploited (3-4 sentences)"
	}

	Guidelines:
	1. Integrate all provided data (CVSS score, affected products, CWE IDs) for a professional analysis.
	2. 'analysis_summary': Include vulnerability significance, potential impact, and technical characteristics.
	3. 'affected_systems': Describe the types of systems or software affected, based on the CVE description.
	4. 'affected_products': List specific product names affected, based on the CPE information provided.
	5. 'technical_details': Be specific and technical. Include potential impact and attack vectors. Do not mention the CVE ID in this field.
	6. 'recommendation': Provide actionable and concrete measures.
	7. 'vulnerability_type': Use standard cybersecurity terms in English.
	8. For all fields except 'analysis_summary', avoid mentioning the CVE ID directly.

	Description: %s

	%s

	%s
	CWE IDs: %s

	Provide a valid JSON response. Use Korean for all fields except 'vulnerability_type' and 'affected_products'.
	`,
		cve.ID,
		cve.Description,
		cvssInfo,
		affectedProductsInfo,
		strings.Join(cve.CWEIDs, ", "),
	)

	return prompt, nil
}

func analyzeWithChatGPT(openaiClient common.OpenAIClient, ctx context.Context, prompt string) (string, error) {
	resp, err := openaiClient.CreateChatCompletion(
		ctx,
		openai.ChatCompletionRequest{
			Model: openai.GPT4oMini, // GPT-4 모델 사용
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
		},
	)

	if err != nil {
		return "", fmt.Errorf("ChatGPT API error: %w", err)
	}

	return resp.Choices[0].Message.Content, nil
}

func parseResponse(response string) (*models.AIAnalysis, error) {
	// ```json으로 시작하는 부분 찾기
	startIndex := strings.Index(response, "```json")
	if startIndex == -1 {
		return nil, fmt.Errorf("JSON 시작 태그를 찾을 수 없습니다")
	}

	// JSON 내용 추출
	jsonContent := response[startIndex+7:]
	endIndex := strings.Index(jsonContent, "```")
	if endIndex == -1 {
		return nil, fmt.Errorf("JSON 종료 태그를 찾을 수 없습니다")
	}
	jsonContent = jsonContent[:endIndex]

	// 추출된 JSON 파싱
	var analysis models.AIAnalysis
	err := json.Unmarshal([]byte(jsonContent), &analysis)
	if err != nil {
		return nil, fmt.Errorf("AI 응답 파싱 실패: %w", err)
	}

	// 파싱된 데이터 출력
	// fmt.Printf("Analysis Summary: %s\n", analysis.AnalysisSummary)
	// fmt.Printf("Affected Systems: %s\n", analysis.AffectedSystems)
	// fmt.Printf("Affected Products: %v\n", analysis.AffectedProducts)
	// fmt.Printf("Vulnerability Type: %s\n", analysis.VulnerabilityType)
	// fmt.Printf("Risk Level: %d\n", analysis.RiskLevel)
	// fmt.Printf("Recommendation: %s\n", analysis.Recommendation)
	// fmt.Printf("Technical Details: %s\n", analysis.TechnicalDetails)

	return &analysis, nil
}
