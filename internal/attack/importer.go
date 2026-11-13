package attack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/LordXapose/threat-graph/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	datasetName   = "mitre-attack"
	maxBundleSize = 512 << 20
)

type bundle struct {
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type               string              `json:"type"`
	ID                 string              `json:"id"`
	Name               string              `json:"name"`
	ShortName          string              `json:"x_mitre_shortname"`
	Description        string              `json:"description"`
	ExternalReferences []externalReference `json:"external_references"`
	KillChainPhases    []killChainPhase    `json:"kill_chain_phases"`
	Platforms          []string            `json:"x_mitre_platforms"`
	Deprecated         bool                `json:"x_mitre_deprecated"`
	Revoked            bool                `json:"revoked"`
	RelationshipType   string              `json:"relationship_type"`
	SourceRef          string              `json:"source_ref"`
	TargetRef          string              `json:"target_ref"`
}

type externalReference struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
}

type killChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

type importedTechnique struct {
	attackID  string
	parentID  string
	model     models.Technique
	tactics   []string
	platforms []string
}

// ImportSTIX imports ATT&CK STIX objects in a single transaction. Re-importing
// the same bundle updates catalog entries and the corresponding version record.
func ImportSTIX(database *gorm.DB, reader io.Reader, version string) (int, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		return 0, fmt.Errorf("dataset version is required")
	}

	content, err := io.ReadAll(io.LimitReader(reader, maxBundleSize+1))
	if err != nil {
		return 0, fmt.Errorf("read STIX bundle: %w", err)
	}
	if len(content) > maxBundleSize {
		return 0, fmt.Errorf("STIX bundle exceeds %d bytes", maxBundleSize)
	}

	var data bundle
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&data); err != nil {
		return 0, fmt.Errorf("decode STIX bundle: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return 0, fmt.Errorf("decode STIX bundle: unexpected trailing data")
	}

	tactics := make(map[string]models.Tactic)
	for _, object := range data.Objects {
		if object.Type == "x-mitre-tactic" && object.ShortName != "" && object.Name != "" {
			tactics[object.ShortName] = models.Tactic{Name: object.Name, ShortName: object.ShortName}
		}
	}

	var techniques []importedTechnique
	stixToAttackID := make(map[string]string)
	for _, object := range data.Objects {
		if object.Type != "attack-pattern" {
			continue
		}
		attackID := ""
		for _, reference := range object.ExternalReferences {
			if reference.SourceName == datasetName && strings.HasPrefix(reference.ExternalID, "T") {
				attackID = reference.ExternalID
				break
			}
		}
		if attackID == "" || object.Name == "" {
			continue
		}

		var phaseNames []string
		for _, phase := range object.KillChainPhases {
			if phase.KillChainName == datasetName && phase.PhaseName != "" {
				phaseNames = append(phaseNames, phase.PhaseName)
			}
		}
		techniques = append(techniques, importedTechnique{
			attackID: attackID,
			model: models.Technique{
				ATTACKID:    attackID,
				Name:        object.Name,
				Description: object.Description,
				Deprecated:  object.Deprecated,
				Revoked:     object.Revoked,
			},
			tactics:   phaseNames,
			platforms: object.Platforms,
		})
		stixToAttackID[object.ID] = attackID
	}
	if len(techniques) == 0 {
		return 0, fmt.Errorf("STIX bundle contains no MITRE ATT&CK techniques")
	}

	for _, object := range data.Objects {
		if object.Type != "relationship" || object.RelationshipType != "subtechnique-of" {
			continue
		}
		child, childExists := stixToAttackID[object.SourceRef]
		parent, parentExists := stixToAttackID[object.TargetRef]
		if !childExists || !parentExists {
			continue
		}
		for index := range techniques {
			if techniques[index].attackID == child {
				techniques[index].parentID = parent
				break
			}
		}
	}

	hash := sha256.Sum256(content)
	importedAt := time.Now().UTC()
	err = database.Transaction(func(tx *gorm.DB) error {
		for shortName, tactic := range tactics {
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "short_name"}},
				DoUpdates: clause.AssignmentColumns([]string{"name"}),
			}).Create(&tactic).Error; err != nil {
				return fmt.Errorf("upsert tactic %q: %w", tactic.ShortName, err)
			}
			if err := tx.Where("short_name = ?", shortName).First(&tactic).Error; err != nil {
				return fmt.Errorf("load tactic %q: %w", shortName, err)
			}
			tactics[shortName] = tactic
		}

		attackIDs := make(map[string]models.Technique, len(techniques))
		for _, item := range techniques {
			if err := tx.Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "attack_id"}},
				DoUpdates: clause.AssignmentColumns([]string{
					"name", "description", "deprecated", "revoked",
				}),
			}).Create(&item.model).Error; err != nil {
				return fmt.Errorf("upsert technique %q: %w", item.attackID, err)
			}

			var technique models.Technique
			if err := tx.Where("attack_id = ?", item.attackID).First(&technique).Error; err != nil {
				return fmt.Errorf("load technique %q: %w", item.attackID, err)
			}

			var relatedTactics []models.Tactic
			for _, name := range item.tactics {
				if tactic, exists := tactics[name]; exists {
					relatedTactics = append(relatedTactics, tactic)
				}
			}
			if err := tx.Model(&technique).Association("Tactics").Replace(relatedTactics); err != nil {
				return fmt.Errorf("replace tactics for %q: %w", item.attackID, err)
			}

			relatedPlatforms := make([]models.Platform, 0, len(item.platforms))
			for _, name := range item.platforms {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				platform := models.Platform{Name: name}
				if err := tx.Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "name"}},
					DoNothing: true,
				}).Create(&platform).Error; err != nil {
					return fmt.Errorf("upsert platform %q: %w", name, err)
				}
				if err := tx.Where("name = ?", name).First(&platform).Error; err != nil {
					return fmt.Errorf("load platform %q: %w", name, err)
				}
				relatedPlatforms = append(relatedPlatforms, platform)
			}
			if err := tx.Model(&technique).Association("Platforms").Replace(relatedPlatforms); err != nil {
				return fmt.Errorf("replace platforms for %q: %w", item.attackID, err)
			}
			attackIDs[item.attackID] = technique
		}

		for _, item := range techniques {
			technique := attackIDs[item.attackID]
			var parentID *uint
			if parent, exists := attackIDs[item.parentID]; exists {
				id := parent.ID
				parentID = &id
			}
			if err := tx.Model(&technique).Update("parent_id", parentID).Error; err != nil {
				return fmt.Errorf("update parent for %q: %w", item.attackID, err)
			}
		}

		record := models.DatasetImport{
			Dataset:     datasetName,
			Version:     version,
			SHA256:      hex.EncodeToString(hash[:]),
			ObjectCount: len(data.Objects),
			ImportedAt:  importedAt,
		}
		if err := tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "dataset"}, {Name: "version"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"sha256", "object_count", "imported_at",
			}),
		}).Create(&record).Error; err != nil {
			return fmt.Errorf("record dataset import: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(techniques), nil
}
