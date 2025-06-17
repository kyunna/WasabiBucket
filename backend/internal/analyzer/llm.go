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

func generatePromptCWE(cweData *models.CWEData) (string, error) {
	if cweData == nil {
		return "", fmt.Errorf("input CWEData is nil")
	}

	var sb strings.Builder
	sb.WriteString(`As a cybersecurity expert, summarize the following CWE information for dual usage:

	1. "summaryEn": A precise, technical summary in English, intended for internal use in CVE analysis and retrieval-augmented generation (RAG). Use formal language. Max 4 sentences.

	2. "summaryKo": A short, intuitive summary in Korean that can be shown to general users on the frontend. Focus on clarity and brevity (1–2 sentences).

	Provide a valid JSON response in the following format, without markdown code block:

	{
		"summaryEn": "...",
		"summaryKo": "..."
	}
	`) 

	sb.WriteString(fmt.Sprintf("CWE ID: CWE-%s\n", cweData.ID))
	sb.WriteString(fmt.Sprintf("Name: %s\n", cweData.Name))
	sb.WriteString(fmt.Sprintf("Description: %s\n", cweData.Description))

	if cweData.ExtendedDescription != "" {
		sb.WriteString(fmt.Sprintf("\nExtended Description: %s\n", cweData.ExtendedDescription))
	}

	if cweData.LikelihoodOfExploit != "" {
		sb.WriteString(fmt.Sprintf("\nLikelihood of Exploit: %s\n", cweData.LikelihoodOfExploit))
	}

	if len(cweData.CommonConsequences) > 0 {
		sb.WriteString("\nCommon Consequences:\n")
		for _, cc := range cweData.CommonConsequences {
			sb.WriteString(fmt.Sprintf("- Scope: %s\n", strings.Join(cc.Scope, ", ")))
			sb.WriteString(fmt.Sprintf("  Impact: %s\n", strings.Join(cc.Impact, ", ")))
			if cc.Note != "" {
				sb.WriteString(fmt.Sprintf("  Note: %s\n", cc.Note))
			}
		}
	}

	return sb.String(), nil
}

func generatePromptCVE(db common.DatabaseConnector, cveID string) (string, error) {
	var cve models.CVEData
	var affectedProducts, cweIDs pq.StringArray

	// 1. Load CVE info
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


	// 2. Compose CVSS info
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

	// 3. Compose affected product info
	var affectedProductsInfo string
	if len(cve.AffectedProducts) > 0 {
		affectedProductsInfo = fmt.Sprintf("Affected Products: %s", strings.Join(cve.AffectedProducts, ", "))
	} else {
		affectedProductsInfo = "No affected products information available"
	}

	// 4. Fetch CWE summaries
	var cweSummaries []string
	for _, cweID := range cve.CWEIDs {
		var summary string
		err := db.QueryRow(`SELECT summary_en FROM cwe_info WHERE cwe_id = $1`, cweID).Scan(&summary)
		if err == nil && summary != "" {
			cweSummaries = append(cweSummaries, fmt.Sprintf("%s: %s", cweID, summary))
		}
	}
	cweInfo := "No CWE summaries available"
	if len(cweSummaries) > 0 {
		cweInfo = "CWE Summaries:\n" + strings.Join(cweSummaries, "\n")
	}

	// 5. Count PoC data
	var githubCount, edbCount int
	_ = db.QueryRow(`SELECT COUNT(*) FROM poc_data WHERE cve_id = $1 AND source = 'GitHub'`, cveID).Scan(&githubCount)
	_ = db.QueryRow(`SELECT COUNT(*) FROM poc_data WHERE cve_id = $1 AND source = 'Exploit-DB'`, cveID).Scan(&edbCount)

	var pocInfo string
	if githubCount+edbCount == 0 {
		pocInfo = "No public proof-of-concept (PoC) available."
	} else {
		pocInfo = fmt.Sprintf("PoC Availability:\n- GitHub: %d file(s)\n- Exploit-DB: %d entry(ies)", githubCount, edbCount)
	}

	// 6. Compose final prompt
	prompt := fmt.Sprintf(`
	As a cybersecurity expert, analyze the following vulnerability (%s) and provide a comprehensive summary in JSON format.

	Your response must be structured as:

	{
		"analysis_summary": "...",        // (Korean) Summary of the vulnerability (max 5 sentences)
		"affected_systems": "...",        // (Korean) Impacted systems/software types
		"affected_products": ["..."],     // (English) Specific product names (CPE-based)
		"vulnerability_type": "...",      // (English) Vulnerability category (e.g., XSS, SQLi)
		"risk_level": 0,                  // (Integer) 0 = Low, 1 = Medium, 2 = High
		"recommendation": "...",          // (Korean) Specific mitigation steps (2–3 sentences)
		"technical_details": "..."        // (Korean) Technical explanation & impact (3–4 sentences)
	}

	Guidelines:
	1. Use all available information below: CVE details, CVSS score, affected products, CWE summaries, and PoC availability.
	2. Be concise yet technical. Emphasize practical impact and exploitability.
	3. Use Korean for all fields except 'vulnerability_type' and 'affected_products'.
	4. Do NOT include the CVE ID in any field except 'analysis_summary'.
	5. Prioritize CWE summaries to understand vulnerability type and consequences.
	6. Consider PoC availability when judging risk level and recommending mitigations.
	7. If public PoC is available, reflect this in the 'analysis_summary' as a factor of exploit likelihood.

	---

	CVE Description:
	%s

	CVSS Information:
	%s

	Affected Products:
	%s

	Relevant CWE Summaries:
	%s

	Public Proof-of-Concept (PoC) Availability:
	%s
	`,
		cve.ID,
		cve.Description,
		cvssInfo,
		affectedProductsInfo,
		cweInfo,
		pocInfo,
	)

	return prompt, nil
}

func callChatGPT(openaiClient common.OpenAIClient, ctx context.Context, prompt string) (string, error)  {
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

func parseCVEAnalysisResponse(response string) (*models.CVEInfo, error) {
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
	var analysis models.CVEInfo
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

func parseCWEInfoResponse(cweID string, resp string) (*models.CWEInfo, error) {
	// Remove ```json block if present
	if startIdx := strings.Index(resp, "```json"); startIdx != -1 {
		resp = resp[startIdx+7:]
		if endIdx := strings.Index(resp, "```"); endIdx != -1 {
			resp = resp[:endIdx]
		}
	}

	// Parse JSON content 
	var result struct {
		SummaryEn string `json:"summaryEn"`
		SummaryKo string `json:"summaryKo"`
	}
	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		return nil, fmt.Errorf("failed to parse CWE summary resp: %w", err)
	}

	return &models.CWEInfo{
		CWEID: cweID,
		SummaryEn: result.SummaryEn,
		SummaryKo: result.SummaryKo,
		SourceURL: fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(cweID, "CWE-")),
	}, nil
}
