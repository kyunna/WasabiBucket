package common 

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

type SQSPublisher interface {
    SendMessage(message string) error
}

type SQSConsumer interface {
    ReceiveMessage() (*sqs.Message, error)
    DeleteMessage(receiptHandle *string) error
}

type SQSClient struct {
	svc      *sqs.SQS
	queueURL string
}

type SQSPublisherInitializer interface {
    InitSQSPublisher(config ConfigLoader) (SQSPublisher, error)
}

type SQSConsumerInitializer interface {
    InitSQSConsumer(config ConfigLoader) (SQSConsumer, error)
}

type SQSInitializer struct{}

func NewSQSPublisherInitializer() SQSPublisherInitializer {
    return &SQSInitializer{}
}

func NewSQSConsumerInitializer() SQSConsumerInitializer {
    return &SQSInitializer{}
}

func (s *SQSInitializer) InitSQSPublisher(config ConfigLoader) (SQSPublisher, error) {
    return s.initSQSClient(config)
}

func (s *SQSInitializer) InitSQSConsumer(config ConfigLoader) (SQSConsumer, error) {
    return s.initSQSClient(config)
}

func (c *SQSInitializer) initSQSClient(config ConfigLoader) (*SQSClient, error) {
	sqsConfig := config.GetSQSConfig()
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(sqsConfig.Region),
		Credentials: credentials.NewStaticCredentials(sqsConfig.AccessKey, sqsConfig.SecretAccessKey, ""),
	})
	if err != nil {
		return nil, err
	}

	sqsService := sqs.New(sess)

	return &SQSClient{
		svc: sqsService,
		queueURL:   sqsConfig.QueueURL,
	}, nil
}

func (c *SQSClient) SendMessage(message string) error {
	_, err := c.svc.SendMessage(&sqs.SendMessageInput{
		DelaySeconds: aws.Int64(10),
		MessageBody: aws.String(message),
		QueueUrl:    &c.queueURL,
	})

	return err
}

func (c *SQSClient) ReceiveMessage() (*sqs.Message, error) {
	result, err := c.svc.ReceiveMessage(&sqs.ReceiveMessageInput{
		QueueUrl:            &c.queueURL,
		MaxNumberOfMessages: aws.Int64(1),
		WaitTimeSeconds:     aws.Int64(20),
	})
	if err != nil {
		return nil, err
	}
	if len(result.Messages) > 0 {
		return result.Messages[0], nil
	}
	return nil, nil
}

func (c *SQSClient) DeleteMessage(receiptHandle *string) error {
	_, err := c.svc.DeleteMessage(&sqs.DeleteMessageInput{
		QueueUrl:      &c.queueURL,
		ReceiptHandle: receiptHandle,
	})
	return err
}
