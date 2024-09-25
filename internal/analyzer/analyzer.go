package analyzer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"wasabibucket/internal/common"
	"wasabibucket/internal/models"

	"github.com/lib/pq"
	"github.com/sashabaranov/go-openai"
)

type Analyzer struct {
	config       common.ConfigLoader
	db           common.DatabaseConnector
	logger       common.Logger
	sqs          common.SQSConsumer
	openaiClient common.OpenAIClient
}

func New(config common.ConfigLoader) (*Analyzer, error) {
	dbInitializer := common.NewDatabaseInitializer()
	db, err := dbInitializer.InitDatabase(config)
	if err != nil {
		return nil, err
	}

	loggerInitializer := common.NewLoggerInitializer()
	logger, err := loggerInitializer.InitLogger("analyzer", config)
	if err != nil {
		db.Close()
		return nil, err
	}

	sqsInitializer := common.NewSQSConsumerInitializer()
	sqs, err := sqsInitializer.InitSQSConsumer(config)
	if err != nil {
		return nil, err
	}

	openaiInitializer := common.NewOpenAIClientInitializer()
	openaiClient, err := openaiInitializer.InitOpenAIClient(config)
	if err != nil {
		return nil, err
	}

	return &Analyzer{
		config:       config,
		db:           db,
		logger:       logger,
		sqs:          sqs,
		openaiClient: openaiClient,
	}, nil
}

func (a *Analyzer) Close() error {
	var errs []error

	if err := a.db.Close(); err != nil {
		errs = append(errs, fmt.Errorf("Failed to close database: %w", err))
	}

	if fileLogger, ok := a.logger.(*common.FileLogger); ok {
		if err := fileLogger.Close(); err != nil {
			errs = append(errs, fmt.Errorf("Failed to close logger: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("Errors occurred while closing resources: %v", errs)
	}
	return nil
}

func (a *Analyzer) Run(ctx context.Context, maxAnalyzer int64) error {
	a.logger.Printf("Start analyzer\n")

	const (
		defaultInterval    = 60 * time.Second
		shortInterval      = 10 * time.Second
		longPollingTimeout = 20 // SQS Long Polling timeout in seconds
	)

	ticker := time.NewTicker(shortInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Printf("Shutdown signal received, stopping analyzer...")
			return nil
		case <-ticker.C:
			messages, err := a.sqs.ReceiveMessage(maxAnalyzer, longPollingTimeout)
			if err != nil {
				a.logger.Errorf("Error processing SQS messages: %v", err)
				continue
			}

			if len(messages) > 0 {
				for _, message := range messages {
					cveID := *message.Body
					a.logger.Printf("Start analyzing %s", cveID)

					prompt, err := generatePrompt(a.db, cveID)
					if err != nil {
						if err == sql.ErrNoRows {
							a.logger.Printf("No data found for %s from CVE Data", cveID)
							if err := a.sqs.DeleteMessage(message.ReceiptHandle); err != nil {
								a.logger.Errorf("Failed to delete SQS message for non-existent %s: %v", cveID, err)
							} else {
								a.logger.Printf("Delete SQS message for non-existent %s", cveID)
							}
							continue
						}
						a.logger.Errorf("Failed to generate prompt for %s: %v", cveID, err)
						continue
					}

					analysisCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
					defer cancel()

					analysis, err := analyzeWithChatGPT(a.openaiClient, analysisCtx, prompt)
					if err != nil {
						a.logger.Errorf("Failed to analyze %s with ChatGPT: %v", cveID, err)
						continue
					}

					parsedAnalysis, err := parseResponse(analysis)
					if err != nil {
						a.logger.Errorf("Failed to parse AI response for %s: %v", cveID, err)
						continue
					}

					a.logger.Printf("Complete analyzing %s", cveID)

					if err := storeAnalysisResult(a.db, cveID, parsedAnalysis); err != nil {
						a.logger.Errorf("Failed to store analysis result for %s: %v", cveID, err)
						continue
					}

					a.logger.Printf("Update analysis data to DB: %s", cveID)

					if err := a.sqs.DeleteMessage(message.ReceiptHandle); err != nil {
						a.logger.Errorf("Failed to delete SQS message (%s): %v", cveID, err)
					}
				}
				ticker.Reset(shortInterval)
			} else {
				ticker.Reset(defaultInterval)
			}
		}
	}
}

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
	"affected_systems": "Brief description of impacted systems/software",
	"affected_products": ["List", "of", "affected", "product", "names"],
	"vulnerability_type": "Category or type of vulnerability in English",
	"risk_level": 0, // 0: Low, 1: Medium, 2: High, based on CVSS score and severity
	"recommendation": "Specific actions to mitigate or address the vulnerability (2-3 sentences)",
	"technical_details": "Technical specifics, attack vectors, and potential impact if exploited (3-4 sentences)"
	}

	Guidelines:
	1. Integrate all provided data (CVSS score, affected products, CWE IDs) for a professional analysis.
	2. 'analysis_summary': Include vulnerability significance, potential impact, and technical characteristics.
	3. 'technical_details': Be specific and technical. Include potential impact and attack vectors. Do not mention the CVE ID in this field.
	4. 'recommendation': Provide actionable and concrete measures.
	5. 'vulnerability_type': Use standard cybersecurity terms in English.
	6. 'affected_systems': Concise, doesn't require full sentences.
	7. For all fields except 'analysis_summary', avoid mentioning the CVE ID directly.

	Description: %s

	%s

	%s
	CWE IDs: %s

	Provide a valid JSON response. Use Korean for all fields except 'vulnerability_type'.
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

func storeAnalysisResult(db common.DatabaseConnector, cveID string, analysis *models.AIAnalysis) error {
	query := `
        INSERT INTO analysis_data (
            cve_id, analysis_summary, affected_systems, affected_products, 
            vulnerability_type, risk_level, recommendation, 
            technical_details, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT (cve_id) DO UPDATE SET
            analysis_summary = EXCLUDED.analysis_summary,
            affected_systems = EXCLUDED.affected_systems,
            affected_products = EXCLUDED.affected_products,
            vulnerability_type = EXCLUDED.vulnerability_type,
            risk_level = EXCLUDED.risk_level,
            recommendation = EXCLUDED.recommendation,
            technical_details = EXCLUDED.technical_details,
            updated_at = CURRENT_TIMESTAMP
    `
	_, err := db.Exec(query, cveID, analysis.AnalysisSummary, analysis.AffectedSystems,
		pq.Array(analysis.AffectedProducts), analysis.VulnerabilityType,
		analysis.RiskLevel, analysis.Recommendation,
		analysis.TechnicalDetails)
	if err != nil {
		return fmt.Errorf("Failed to store analysis result: %w", err)
	}
	return nil
}
