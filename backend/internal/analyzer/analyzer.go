package analyzer

import (
	"context"
	"fmt"
	"time"

	"wasabibucket/internal/common"
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

			if len(messages) == 0 {
				ticker.Reset(defaultInterval)
				continue
			}

			for _, message := range messages {
				cveID := *message.Body
				a.logger.Printf("%s | Start analyzing", cveID)

				// 1. Exploit-DB PoC 수집 및 저장
				edbResult, err := fetchExploitDBPoC(cveID, a.config.GetExploitDBPath())
				if err != nil {
					a.logger.Errorf("%s | Exploit-DB fetch failed: %v", cveID, err)
				} 

				if len(edbResult) == 0 {
					a.logger.Printf("%s | Exploit-DB PoC: No match found", cveID)
				}

				a.logger.Printf("%s | Exploit-DB PoC: %d entries", cveID, len(edbResult))
				err = storePoCData(a.db, edbResult)
				if err != nil {
					a.logger.Errorf("%s | Failed to store Exploit-DB PoC data: %v", cveID, err)
				} else {
					a.logger.Printf("%s | Exploit-DB PoC data stored", cveID)
				}
				
				// 2. Github PoC 수집 및 저장
				githubResult, err := fetchGitHubPoC(cveID, a.config.GetGitHubToken())
				if err != nil {
					a.logger.Errorf("%s | GitHub PoC fetch failed: %v", cveID, err)
				} 

				if len(githubResult) == 0 {
					a.logger.Printf("%s | GitHub PoC: No match found", cveID)
				}

				a.logger.Printf("%s | GitHub PoC: %d entries", cveID, len(githubResult))
				err = storePoCData(a.db, githubResult)
				if err != nil {
					a.logger.Errorf("%s | Failed to store GitHub PoC data: %v", cveID, err)
				} else {
					a.logger.Printf("%s | GitHub PoC data stored", cveID)
				}

				// 3. CVE 정보 쿼리(프롬프트 생성용)
				cveInfo, err := getCVEInfo(a.db, cveID)	
				if err != nil {
					a.logger.Errorf("%s | CVE information loading failed: %v", cveID, err)
					continue
				}

				// 4. CWE 조회
				for _, cweID := range cveInfo.CWEIDs {
					cweInfo, err := getCWEInfo(a.db, cweID)
					if err != nil {
						a.logger.Errorf("%s | Failed to get cwe info from db: %v", cweID, err)
						continue
					}

					// If there is no CWE information in the DB, collect CWE information and generate a summary
					if cweInfo == nil {
						a.logger.Printf("%s | %s info not found in database. Fetching and analyzing...", cveID, cweID)

						cweData, err := fetchCWEInfo(cweID)
						if err != nil {
							a.logger.Errorf("%s | Failed to fetch %s from MITRE: %v", cveID, cweID, err)
							continue
						}

						err = storeCWEData(a.db, cweData)
						if err != nil {
							a.logger.Errorf("%s | Failed to store detailed data for %s: %v", cveID, cweID, err)
						}
						a.logger.Printf("%s | Detail data for %s stored successfully", cveID, cweID)

						a.logger.Printf("%s | Generating prompt and requesting LLM summary for %s", cveID, cweID)

						prompt, err := generatePromptCWE(cweData)
						if err != nil {
							a.logger.Errorf("%s | Failed to generate prompt for %s: %v", cveID, cweID, err)
							continue
						}

						summaryCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
						summary, err := callChatGPT(a.openaiClient, summaryCtx, prompt)
						cancel()
						if err != nil {
							a.logger.Errorf("%s | Failed to retrieve summary for %s from LLM: %v", cveID, cweID, err)
							continue
						}

						parseCWEInfo, err := parseCWEInfoResponse(cweID, summary)
						if err != nil {
							a.logger.Errorf("%s | Failed to parse summary for %s: %v", cveID, cweID, err)
							continue
						}

						err = storeCWEInfo(a.db, parseCWEInfo)
						if err != nil {
							a.logger.Errorf("%s | Failed to store summary for %s: %v", cveID, cweID, err)
						}
						a.logger.Printf("%s | Summary for %s stored successfully", cveID, cweID)
					}
				}

				// 3. Prompt 생성
				// prompt, err := generatePrompt(a.db, cveID)
				// if err != nil {
				// 	if err == sql.ErrNoRows {
				// 		a.logger.Printf("%s | No CVE data available, deleting message", cveID)
				// 		if err := a.sqs.DeleteMessage(message.ReceiptHandle); err != nil {
				// 			a.logger.Errorf("%s | Failed to delete SQS message: %v", cveID, err)
				// 		} else {
				// 			a.logger.Printf("%s | SQS message deleted", cveID)
				// 		}
				// 		continue
				// 	}
				// 	a.logger.Errorf("%s | Prompt generation failed: %v", cveID, err)
				// 	continue
				// }

				// 4. LLM 호출
				// analysisCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				// analysis, err := analyzeWithChatGPT(a.openaiClient, analysisCtx, prompt)
				// cancel()
				// if err != nil {
				// 	a.logger.Errorf("%s | ChatGPT analysis failed: %v", cveID, err)
				// 	continue
				// }
				// a.logger.Printf("%s | ChatGPT response received", cveID)


				// 5. 분석 결과 저장
				// parsedAnalysis, err := parseResponse(analysis)
				// if err != nil {
				// 	a.logger.Errorf("%s | Failed to parse AI response: %v", cveID, err)
				// 	continue
				// }
				//
				// if err := storeAnalysisResult(a.db, cveID, parsedAnalysis); err != nil {
				// 	a.logger.Errorf("%s | Failed to store analysis result: %v", cveID, err)
				// 	continue
				// }
				// a.logger.Printf("%s | Analysis result stored", cveID)

				// 6. SQS message 삭제
				if err := a.sqs.DeleteMessage(message.ReceiptHandle); err != nil {
					a.logger.Errorf("%s | Failed to delete SQS message: %v", cveID, err)
				} else {
					a.logger.Printf("%s | SQS message deleted", cveID)
				}

				a.logger.Printf("%s | Analysis complete", cveID)
				ticker.Reset(shortInterval)
			}
		}
	}
}
