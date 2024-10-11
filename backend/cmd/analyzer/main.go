package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wasabibucket/internal/analyzer"
	"wasabibucket/internal/common"
)

func main() {
	// Write PID to file
	pid := os.Getpid()
	pidFile := "./analyzer.pid"
	err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", pid)), 0644)
	if err != nil {
		log.Fatalf("Failed to write PID to file: %v", err)
	}
	defer os.Remove(pidFile) // Clean up PID file on exit

	config := common.NewConfig()
	err = config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	a, err := analyzer.New(config)
	if err != nil {
		log.Fatalf("Error creating analyzer: %v", err)
	}
	defer a.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := a.Run(ctx, 2); err != nil {
			log.Printf("Error from analyzer: %v", err)
			cancel()
		}
	}()

	<-sigChan
	log.Println("Shutdown signal received, initiating graceful shutdown...")

	cancel()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 30 * time.Second)
	defer cancelShutdown()
	<-shutdownCtx.Done()

	log.Println("Shutdown complete")

}
