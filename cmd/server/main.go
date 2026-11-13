package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/LordXapose/threat-graph/internal/api"
	"github.com/LordXapose/threat-graph/internal/db"

	"github.com/gin-gonic/gin"
)

func main() {
	address := envOrDefault("API_ADDR", "127.0.0.1:8080")
	writeToken := os.Getenv("API_TOKEN")
	if !isLoopbackAddress(address) && strings.TrimSpace(writeToken) == "" {
		log.Fatal("API_TOKEN must be configured when API_ADDR is not loopback")
	}

	requestsPerMinute := 600
	if value := os.Getenv("API_RATE_LIMIT_PER_MIN"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			log.Fatal("API_RATE_LIMIT_PER_MIN must be a positive integer")
		}
		requestsPerMinute = parsed
	}

	databasePath := envOrDefault("DB_PATH", filepath.Join("data", "threat_graph.db"))
	database, err := db.Open(databasePath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	if err := db.EnsureSchema(database); err != nil {
		log.Fatalf("migrate database: %v", err)
	}
	sqlDatabase, err := database.DB()
	if err != nil {
		log.Fatalf("get database connection: %v", err)
	}
	defer sqlDatabase.Close()

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	api.RegisterRoutes(router, database, api.Config{
		WriteToken:        writeToken,
		RequestsPerMinute: requestsPerMinute,
	})

	server := &http.Server{
		Addr:              address,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("starting ThreatGraph API on %s", address)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("run server: %v", err)
		}
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			log.Fatalf("shutdown server: %v", err)
		}
		if err := <-serverErrors; !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("run server: %v", err)
		}
	}
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
