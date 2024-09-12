package analyzer

import (
	"context"
	"fmt"
	"time"

	"wasabibucket/internal/common"
)

type Analyzer struct {
	config common.ConfigLoader
	db     common.DatabaseConnector
  logger common.Logger
	sqs    common.SQSConsumer
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

	return &Analyzer{
		config: config,
		db:     db,
		logger: logger,
		sqs:    sqs,
	}, nil
}

// 메인 실행 루프, 컨텍스트를 사용한 전체 프로세스의 수명주기 관리
func (a *Analyzer) Run(ctx context.Context, maxAnalyzer int64) error {
	a.logger.Printf("SQS Message polling...")

	const (
		defaultInterval = 60 * time.Second
		shortInterval   = 10 * time.Second
		longPollingTimeout = 20 // SQS Long Polling timeout in seconds
	)

	ticker := time.NewTicker(shortInterval)
	defer ticker.Stop()

	for { 
		select {
		case <-ctx.Done():
			a.logger.Printf("Shotdown signal received, stopping analyzer...")
			return nil
		case <-ticker.C:
			messages, err := a.sqs.ReceiveMessage(maxAnalyzer, longPollingTimeout)
			if err != nil {
				a.logger.Errorf("Error processing SQS messages :%v", err)
				continue
			}

			if len(messages) > 0 {
				for _, message := range messages {
					cveID := *message.Body
					a.logger.Printf("Processing message with CVE ID: %s", cveID)

					prompt, err := generatePrompt(a.db, cveID)

					if err != nil {
						fmt.Println("errrrrr")
					}
					fmt.Println(prompt)

					// if err := a.sqs.DeleteMessage(message.ReceiptHandle); err != nil {
					// 	a.logger.Errorf("Failed to delete SQS message (CVE ID: %s): %v", cveID, err)
					// }
				}
				ticker.Reset(shortInterval)
			} else {
				ticker.Reset(defaultInterval)
			}
		}
	}
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
