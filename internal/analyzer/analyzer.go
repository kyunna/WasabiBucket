package analyzer

import (
	"wasabibucket/internal/common"
)

func New(config *common.Config) (*Analyzer, error) {
	sqsClient, err := sqs.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	llmClient, err := llm.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	dbClient, err := database.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	return &Analyzer{
		cfg: cfg,
		sqs: sqsClient,
		llm: llmClient,
		db:  dbClient,
	}, nil
}

func (a *Analyzer) Run() error {
	for {
		// 1. SQS에서 메시지 가져오기
		message, err := a.sqs.ReceiveMessage()
		if err != nil {
			return err
		}

		// 2. LLM으로 쿼리 및 응답 전달 받기
		response, err := a.llm.ProcessMessage(message)
		if err != nil {
			return err
		}

		// 3. 전달받은 값 ai_analysis에 입력
		if err := a.db.InsertAnalysis(response); err != nil {
			return err
		}
	}
}
