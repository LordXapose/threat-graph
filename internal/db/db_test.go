package db

import (
	"fmt"
	"testing"

	"github.com/LordXapose/threat-graph/internal/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type legacyTechnique struct {
	ID          uint   `gorm:"primaryKey"`
	ATTACKID    string `gorm:"uniqueIndex;not null"`
	Name        string `gorm:"not null"`
	Tactic      string `gorm:"not null"`
	Description string
	Platform    string
	ParentID    *uint
	Parent      *legacyTechnique `gorm:"foreignKey:ParentID"`
}

func (legacyTechnique) TableName() string { return "techniques" }

func TestEnsureSchemaMigratesLegacyTacticAndPlatform(t *testing.T) {
	database, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{TranslateError: true})
	if err != nil {
		t.Fatal(err)
	}
	sqlDatabase, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDatabase.Close() })

	if err := database.AutoMigrate(&legacyTechnique{}); err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&legacyTechnique{
		ATTACKID: "T1059.001", Name: "PowerShell", Tactic: "Execution", Platform: "Windows",
	}).Error; err != nil {
		t.Fatal(err)
	}

	if err := EnsureSchema(database); err != nil {
		t.Fatalf("first EnsureSchema() error = %v", err)
	}
	if err := EnsureSchema(database); err != nil {
		t.Fatalf("second EnsureSchema() error = %v", err)
	}

	var technique models.Technique
	if err := database.Preload("Tactics").Preload("Platforms").
		Where("attack_id = ?", "T1059.001").First(&technique).Error; err != nil {
		t.Fatal(err)
	}
	if len(technique.Tactics) != 1 || technique.Tactics[0].ShortName != "execution" {
		t.Fatalf("migrated tactics = %#v, want one execution tactic", technique.Tactics)
	}
	if len(technique.Platforms) != 1 || technique.Platforms[0].Name != "Windows" {
		t.Fatalf("migrated platforms = %#v, want one Windows platform", technique.Platforms)
	}
}
