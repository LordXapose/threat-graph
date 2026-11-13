package main

import (
	"log"
	"os"
	"path/filepath"

	"ttp-tool-mapper/internal/api"
	"ttp-tool-mapper/internal/db"

	"github.com/gin-gonic/gin"
)

func main() {
	dataDir := filepath.Join(".", "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatalf("create data directory: %v", err)
	}

	databasePath := filepath.Join(dataDir, "ttp_tool_mapper.db")
	database, err := db.Open(databasePath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}

	if err := db.EnsureSchema(database); err != nil {
		log.Fatalf("migrate database: %v", err)
	}
	if err := db.SeedSampleData(database); err != nil {
		log.Fatalf("seed initial data: %v", err)
	}

	router := gin.Default()
	api.RegisterRoutes(router, database)

	log.Println("starting TTP Tool Mapper API on :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("start server: %v", err)
	}
}
