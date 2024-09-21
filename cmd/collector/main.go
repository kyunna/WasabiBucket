package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"wasabibucket/internal/collector"
	"wasabibucket/internal/common"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <interval>", os.Args[0])
	}

	interval, err := strconv.Atoi(os.Args[1])
	if err != nil || interval < 1 || interval > 24 {
		log.Fatalf("Interval must be a number between 1 and 24")
	}

	// Write PID to file
	pid := os.Getpid()
	pidFile := "./collector.pid"
	err = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", pid)), 0644)
	if err != nil {
		log.Fatalf("Failed to write PID to file: %v", err)
	}
	defer os.Remove(pidFile) // Clean up PID file on exit

	config := common.NewConfig()
	err = config.Load()
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
		if err := c.Run(ctx, interval); err != nil {
			log.Printf("Error from collector: %v", err)
			cancel()
		}
	}()

	<-sigChan
	log.Println("Shutdown signal received, initiating graceful shutdown...")

	cancel()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()
	<-shutdownCtx.Done()

	log.Println("Shutdown complete")
}
