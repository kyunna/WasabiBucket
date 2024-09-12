package analyzer

import (
	"fmt"
	"wasabibucket/internal/common"
)

func generatePrompt(db common.DatabaseConnector, cveID string) (string, error) {
	fmt.Printf("%s Hello world!", cveID)
	prompt := "Hello"
	return prompt, nil
}
