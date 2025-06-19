package analyzer

import (
	"context"
	"database/sql"
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
	a.logger.Printf("Start analyzer")

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

				a.logger.Printf("%s | >>>>> Start analysis <<<<<", cveID)

				// Step 1. Collect PoC (Exploit-DB, GitHub)
				a.logger.LogPhaseStart(cveID, "PoC Collection")

				edbResult, err := fetchExploitDBPoC(cveID, a.config.GetExploitDBPath())
				if err != nil {
					a.logger.Errorf("%s | [PoC:Exploit-DB] fetch failed: %v", cveID, err)
				} else if len(edbResult) == 0 {
					a.logger.Printf("%s | [PoC:Exploit-DB] no entries found", cveID)
				} else {
					a.logger.Printf("%s | [PoC:Exploit-DB] %d entries found", cveID, len(edbResult))
					if err := storePoCData(a.db, edbResult); err != nil {
						a.logger.Errorf("%s | [PoC:Exploit-DB] failed to store data: %v", cveID, err)
					} else {
						a.logger.Printf("%s | [PoC:Exploit-DB] data stored", cveID)
					}
				}

				githubResult, err := fetchGitHubPoC(cveID, a.config.GetGitHubToken())
				if err != nil {
					a.logger.Errorf("%s | [PoC:GitHub] fetch failed: %v", cveID, err)
				} else if len(githubResult) == 0 {
					a.logger.Printf("%s | [PoC:GitHub] no entries found", cveID)
				} else {
					a.logger.Printf("%s | [PoC:GitHub] %d entries found", cveID, len(githubResult))
					if err := storePoCData(a.db, githubResult); err != nil {
						a.logger.Errorf("%s | [PoC:GitHub] failed to store data: %v", cveID, err)
					} else {
						a.logger.Printf("%s | [PoC:GitHub] data stored", cveID)
					}
				}

				// Step 2. Process CWE information
				a.logger.LogPhaseStart(cveID, "CWE Processing")

				cveInfo, err := getCVEData(a.db, cveID)	
				if err != nil {
					if err == sql.ErrNoRows {
						a.logger.Printf("%s | [CVE] no data available, deleting message", cveID)
						if err := a.sqs.DeleteMessage(message.ReceiptHandle); err != nil {
							a.logger.Errorf("%s | [SQS] Failed to delete SQS message: %v", cveID, err)
						} else {
							a.logger.Printf("%s | [SQS] SQS message deleted", cveID)
						}
						continue
					}
					a.logger.Errorf("%s | [CVE] data load failed: %v", cveID, err)
					continue
				}

				if len(cveInfo.CWEIDs) == 0 {
					a.logger.Printf("%s | [CWE] no CWE IDs associated with CVE, skipping CWE analysis", cveID)
				} else {
					for _, cweID := range cveInfo.CWEIDs {
						if !isValidCWEID(cweID) {
							a.logger.Printf("%s | [CWE:%s] skipped (invalid CWE ID)", cveID, cweID)
							continue
						}
						id := extractID(cweID)

						cweInfo, err := getCWEInfo(a.db, cweID)
						if err != nil {
							a.logger.Errorf("%s | [CWE:%s] DB lookup failed: %v", cveID, id, err)
							continue
						}
						if cweInfo == nil {
							a.logger.Printf("%s | [CWE:%s] not found in DB, fetching from MITRE...", cveID, id)

							cweData, err := fetchCWEInfo(cweID)
							if err != nil {
								a.logger.Errorf("%s | [CWE:%s] fetch failed: %v", cveID, id, err)
								continue
							}

							err = storeCWEData(a.db, cweData)
							if err != nil {
								a.logger.Errorf("%s | [CWE:%s] failed to store detailed data: %v", cveID, id, err)
							}
							a.logger.Printf("%s | [CWE:%s] detail data stored", cveID, id) 

							prompt, err := generatePromptCWE(cweData)
							if err != nil {
								a.logger.Errorf("%s | [CWE:%s] prompt generation failed: %v", cveID, id, err)
								continue
							}

							summaryCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
							summary, err := callChatGPT(a.openaiClient, summaryCtx, prompt)
							cancel()
							if err != nil {
								a.logger.Errorf("%s | [CWE:%s] LLM request failed: %v", cveID, id, err)
								continue
							}

							parsed, err := parseCWEInfoResponse(cweID, summary)
							if err != nil {
								a.logger.Errorf("%s | [CWE:%s] failed to parse LLM response: %v", cveID, id, err)
								continue
							}

							err = storeCWEInfo(a.db, parsed)
							if err != nil {
								a.logger.Errorf("%s | [CWE:%s] failed to store summary data: %v", cveID, id, err)
							}
							a.logger.Printf("%s | [CWE:%s] summary stored", cveID, id)
						} else {
							a.logger.Printf("%s | [CWE:%s] summary loaded" ,cveID, id)
						}
					}
				}

				// Step 3. Analyze CVE
				a.logger.LogPhaseStart(cveID, "CVE Prompt & Analysis")

				prompt, err := generatePromptCVE(a.db, cveID)
				if err != nil {
					if err == sql.ErrNoRows {
						a.logger.Printf("%s | [CVE] no data available, deleting message", cveID)
						if err := a.sqs.DeleteMessage(message.ReceiptHandle); err != nil {
							a.logger.Errorf("%s | [SQS] Failed to delete SQS message: %v", cveID, err)
						} else {
							a.logger.Printf("%s | [SQS] SQS message deleted", cveID)
						}
						continue
					}
					a.logger.Errorf("%s | [CVE] prompt generation failed: %v", cveID, err)
					continue
				}
				a.logger.Printf("%s | [CVE] prompt generated", cveID)

				analysisCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				analysis, err := callChatGPT(a.openaiClient, analysisCtx, prompt)
				cancel()
				if err != nil {
					a.logger.Errorf("%s | [CVE] LLM request failed: %v", cveID, err)
					continue
				}
				a.logger.Printf("%s | [CVE] LLM response received", cveID)

				parsed, err := parseCVEAnalysisResponse(analysis)
				if err != nil {
					a.logger.Errorf("%s | [CVE] failed to parse LLM response: %v", cveID, err)
					continue
				}

				if err := storeAnalysisResult(a.db, cveID, parsed); err != nil {
					a.logger.Errorf("%s | [CVE] failed to store analysis result: %v", cveID, err)
					continue
				}
				a.logger.Printf("%s | [CVE] analysis result stored", cveID)

				if err := a.sqs.DeleteMessage(message.ReceiptHandle); err != nil {
					a.logger.Errorf("%s | [SQS] Failed to delete SQS message: %v", cveID, err)
				} else {
					a.logger.Printf("%s | [SQS] SQS message deleted", cveID)
				}

				a.logger.Printf("%s | <<<<< analysis complete >>>>>", cveID)
				ticker.Reset(shortInterval)
			}
		}
	}
}
