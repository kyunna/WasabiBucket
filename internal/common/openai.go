package common

import (
	"context"

	"github.com/sashabaranov/go-openai"
)

type OpenAIClient interface {
	CreateChatCompletion(ctx context.Context, request openai.ChatCompletionRequest) (openai.ChatCompletionResponse, error)
}

type OpenAIClientInitializer interface {
	InitOpenAIClient(config ConfigLoader) (OpenAIClient, error)
}

type OpenAIClientWrapper struct {
	client *openai.Client
}

func (w *OpenAIClientWrapper) CreateChatCompletion(ctx context.Context, request openai.ChatCompletionRequest) (openai.ChatCompletionResponse, error) {
	return w.client.CreateChatCompletion(ctx, request)
}

type DefaultOpenAIClientInitializer struct{}

func NewOpenAIClientInitializer() OpenAIClientInitializer {
	return &DefaultOpenAIClientInitializer{}
}

func (i *DefaultOpenAIClientInitializer) InitOpenAIClient(config ConfigLoader) (OpenAIClient, error) {
	client := openai.NewClient(config.GetGPTAPIKey())
	return &OpenAIClientWrapper{client: client}, nil
}
