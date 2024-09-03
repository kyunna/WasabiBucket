package collector

import (
	"wasabibucket/internal/common"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

type SQSPublisher struct {
	svc      *sqs.SQS
	queueURL string
}

func NewSQSPublisher(config *common.Config) (*SQSPublisher, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(config.AWSConfig.Region),
		Credentials: credentials.NewStaticCredentials(config.AWSConfig.AccessKey, config.AWSConfig.SecretAccessKey, ""),
	})
	if err != nil {
		return nil, err
	}

	svc := sqs.New(sess)

	return &SQSPublisher{
		svc:      svc,
		queueURL: config.AWSConfig.SQSQueueURL,
	}, nil
}

func (p *SQSPublisher) PublishCVEUpdate(cveID string) error {
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
