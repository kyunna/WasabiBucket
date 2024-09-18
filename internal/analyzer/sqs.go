package analyzer

import (
	"context"
	"time"
)

func (a *Analyzer) processMessages(ctx context.Context, maxAnalyzer int64) error {
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
					a.logger.Printf("Processing message with CVE ID: %s", cveID)

					prompt, err := generatePrompt(a.db, cveID)
					if err != nil {
						a.logger.Errorf("Failed to generate prompt for CVE ID %s: %v", cveID, err)
						continue
					}

					analysisCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
					defer cancel()

					analysis, err := a.analyzeWithChatGPT(analysisCtx, prompt)
					if err != nil {
						a.logger.Errorf("Failed to analyze CVE ID %s with ChatGPT: %v", cveID, err)
						continue
					}

					a.logger.Printf("Analysis for CVE ID %s: %s", cveID, analysis)

					if err := a.storeAnalysisResult(cveID, analysis); err != nil {
						a.logger.Errorf("Failed to store analysis result for CVE ID %s: %v", cveID, err)
						continue
					}

					if err := a.sqs.DeleteMessage(message.ReceiptHandle); err != nil {
						a.logger.Errorf("Failed to delete SQS message (CVE ID: %s): %v", cveID, err)
					}
				}
				ticker.Reset(shortInterval)
			} else {
				ticker.Reset(defaultInterval)
			}
		}
	}
}
