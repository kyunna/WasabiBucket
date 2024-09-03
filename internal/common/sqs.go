package common 

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

type SQSClient struct {
	svc      *sqs.SQS
	queueURL string
}

func NewSQSClient(config *Config) (*SQSClient, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(config.SQSConfig.Region),
		Credentials: credentials.NewStaticCredentials(config.SQSConfig.AccessKey, config.SQSConfig.SecretAccessKey, ""),
	})
	if err != nil {
		return nil, err
	}

	svc := sqs.New(sess)

	return &SQSClient{
		svc:      svc,
		queueURL: config.SQSConfig.SQSQueueURL,
	}, nil
}

func (p *SQSClient) PublishCVEUpdate(cveID string) error {
	_, err := p.svc.SendMessage(&sqs.SendMessageInput{
		DelaySeconds: aws.Int64(10),
		// MessageAttributes: map[string]*sqs.MessageAttributeValue{
		// 	"CVE": {
		// 		DataType:    aws.String("String"),
		// 		StringValue: aws.String("Analyze target CVE ID"),
		// 	},
		// },
		MessageBody: aws.String(cveID),
		QueueUrl:    &p.queueURL,
	})

	return err
}
