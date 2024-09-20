package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wasabibucket/internal/collector"
	"wasabibucket/internal/common"
)

func main() {
	config := common.NewConfig()
	err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	c, err := collector.New(config)
	if err != nil {
		log.Fatalf("Error creating collector: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := c.Run(ctx); err != nil {
			log.Printf("Error from collector: %v", err)
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
