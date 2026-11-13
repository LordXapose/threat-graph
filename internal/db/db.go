package db

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ttp-tool-mapper/internal/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func Open(path string) (*gorm.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	database, err := gorm.Open(sqlite.Open(path), &gorm.Config{TranslateError: true})
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	return database, nil
}

func EnsureSchema(database *gorm.DB) error {
	if err := database.AutoMigrate(
		&models.Tactic{},
		&models.Platform{},
		&models.Technique{},
		&models.Tool{},
		&models.Procedure{},
		&models.Detection{},
		&models.DatasetImport{},
	); err != nil {
		return err
	}
	return migrateLegacyCatalogFields(database)
}

func migrateLegacyCatalogFields(database *gorm.DB) error {
	if database.Migrator().HasColumn("techniques", "tactic") {
		var rows []struct {
			ID     uint
			Tactic string
		}
		if err := database.Table("techniques").Select("id, tactic").Where("tactic <> ''").Scan(&rows).Error; err != nil {
			return fmt.Errorf("read legacy technique tactics: %w", err)
		}
		for _, row := range rows {
			shortName := slug(row.Tactic)
			if shortName == "" {
				continue
			}
			tactic := models.Tactic{Name: row.Tactic, ShortName: shortName}
			if err := database.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "short_name"}},
				DoUpdates: clause.AssignmentColumns([]string{"name"}),
			}).Create(&tactic).Error; err != nil {
				return fmt.Errorf("migrate legacy tactic %q: %w", row.Tactic, err)
			}
			if err := database.Where("short_name = ?", shortName).First(&tactic).Error; err != nil {
				return fmt.Errorf("load migrated tactic %q: %w", shortName, err)
			}
			if err := database.Exec(
				"INSERT OR IGNORE INTO technique_tactics (technique_id, tactic_id) VALUES (?, ?)",
				row.ID, tactic.ID,
			).Error; err != nil {
				return fmt.Errorf("associate migrated tactic %q: %w", shortName, err)
			}
		}
	}

	if database.Migrator().HasColumn("techniques", "platform") {
		var rows []struct {
			ID       uint
			Platform string
		}
		if err := database.Table("techniques").Select("id, platform").Where("platform <> ''").Scan(&rows).Error; err != nil {
			return fmt.Errorf("read legacy technique platforms: %w", err)
		}
		for _, row := range rows {
			name := strings.TrimSpace(row.Platform)
			if name == "" {
				continue
			}
			platform := models.Platform{Name: name}
			if err := database.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "name"}},
				DoNothing: true,
			}).Create(&platform).Error; err != nil {
				return fmt.Errorf("migrate legacy platform %q: %w", name, err)
			}
			if err := database.Where("name = ?", name).First(&platform).Error; err != nil {
				return fmt.Errorf("load migrated platform %q: %w", name, err)
			}
			if err := database.Exec(
				"INSERT OR IGNORE INTO technique_platforms (technique_id, platform_id) VALUES (?, ?)",
				row.ID, platform.ID,
			).Error; err != nil {
				return fmt.Errorf("associate migrated platform %q: %w", name, err)
			}
		}
	}
	return nil
}

func slug(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), "-")
}
