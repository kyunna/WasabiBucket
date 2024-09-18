package analyzer

import (
	"context"
	"fmt"
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

func (a *Analyzer) Run(ctx context.Context, maxAnalyzer int64) error {
	return a.processMessages(ctx, maxAnalyzer)
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
