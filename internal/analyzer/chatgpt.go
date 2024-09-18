package analyzer

import (
	"context"
	"fmt"

	"github.com/sashabaranov/go-openai"
)

func (a *Analyzer) analyzeWithChatGPT(ctx context.Context, prompt string) (string, error) {
	resp, err := a.openaiClient.CreateChatCompletion(
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
