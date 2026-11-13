package db

import (
	"fmt"
	"os"
	"path/filepath"

	"ttp-tool-mapper/internal/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Open(path string) (*gorm.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	database, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	return database, nil
}

func EnsureSchema(database *gorm.DB) error {
	return database.AutoMigrate(
		&models.Technique{},
		&models.Tool{},
		&models.Procedure{},
		&models.Detection{},
	)
}

func SeedSampleData(database *gorm.DB) error {
	var techniqueCount int64
	if err := database.Model(&models.Technique{}).Count(&techniqueCount).Error; err != nil {
		return fmt.Errorf("count techniques: %w", err)
	}
	if techniqueCount > 0 {
		return nil
	}

	technique := models.Technique{
		ATTACKID:    "T1059.001",
		Name:        "PowerShell",
		Tactic:      "Execution",
		Description: "Adversaries may use PowerShell to execute commands and scripts.",
		Platform:    "Windows",
	}
	if err := database.Create(&technique).Error; err != nil {
		return fmt.Errorf("create technique: %w", err)
	}

	tool := models.Tool{
		Name:        "PowerShell",
		Category:    "Execution",
		Vendor:      "Microsoft",
		Description: "Command shell and scripting environment used in Windows environments.",
	}
	if err := database.Create(&tool).Error; err != nil {
		return fmt.Errorf("create tool: %w", err)
	}

	procedure := models.Procedure{
		ToolID:         tool.ID,
		TechniqueID:    technique.ID,
		Summary:        "Launch a PowerShell process and invoke a script block for remote execution.",
		CommandExample: "powershell -nop -enc <base64>",
		Notes:          "This is a sample mapping used for research and lab setup.",
	}
	if err := database.Create(&procedure).Error; err != nil {
		return fmt.Errorf("create procedure: %w", err)
	}

	detection := models.Detection{
		TechniqueID: technique.ID,
		Type:        "sigma",
		Content:     "Title: PowerShell command invocation\nLogsource: ...",
		Source:      "research-sample",
	}
	if err := database.Create(&detection).Error; err != nil {
		return fmt.Errorf("create detection: %w", err)
	}

	return nil
}
