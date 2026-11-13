package attack

import (
	"fmt"
	"strings"
	"testing"

	"github.com/LordXapose/threat-graph/internal/db"
	"github.com/LordXapose/threat-graph/internal/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestImportSTIXIsRepeatableAndRecordsRelationships(t *testing.T) {
	database := openTestDatabase(t)
	const stix = `{
	  "objects": [
	    {
	      "type": "x-mitre-tactic",
	      "id": "x-mitre-tactic--execution",
	      "name": "Execution",
	      "x_mitre_shortname": "execution"
	    },
	    {
	      "type": "attack-pattern",
	      "id": "attack-pattern--parent",
	      "name": "Parent technique",
	      "description": "Parent description",
	      "external_references": [{"source_name": "mitre-attack", "external_id": "T1000"}],
	      "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
	      "x_mitre_platforms": ["Windows"]
	    },
	    {
	      "type": "attack-pattern",
	      "id": "attack-pattern--child",
	      "name": "Child technique",
	      "external_references": [{"source_name": "mitre-attack", "external_id": "T1000.001"}],
	      "x_mitre_platforms": ["Linux"]
	    },
	    {
	      "type": "relationship",
	      "relationship_type": "subtechnique-of",
	      "source_ref": "attack-pattern--child",
	      "target_ref": "attack-pattern--parent"
	    }
	  ]
	}`

	for range 2 {
		count, err := ImportSTIX(database, strings.NewReader(stix), "v-test")
		if err != nil {
			t.Fatalf("ImportSTIX() error = %v", err)
		}
		if count != 2 {
			t.Fatalf("ImportSTIX() count = %d, want 2", count)
		}
	}

	var techniqueCount, importCount int64
	if err := database.Model(&models.Technique{}).Count(&techniqueCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Model(&models.DatasetImport{}).Count(&importCount).Error; err != nil {
		t.Fatal(err)
	}
	if techniqueCount != 2 || importCount != 1 {
		t.Fatalf("techniques/import records = %d/%d, want 2/1", techniqueCount, importCount)
	}

	var child models.Technique
	if err := database.Preload("Parent").Preload("Platforms").Where("attack_id = ?", "T1000.001").First(&child).Error; err != nil {
		t.Fatal(err)
	}
	if child.Parent == nil || child.Parent.ATTACKID != "T1000" {
		t.Fatalf("child parent = %#v, want T1000", child.Parent)
	}
	if len(child.Platforms) != 1 || child.Platforms[0].Name != "Linux" {
		t.Fatalf("child platforms = %#v, want Linux", child.Platforms)
	}

	var parent models.Technique
	if err := database.Preload("Tactics").Where("attack_id = ?", "T1000").First(&parent).Error; err != nil {
		t.Fatal(err)
	}
	if len(parent.Tactics) != 1 || parent.Tactics[0].ShortName != "execution" {
		t.Fatalf("parent tactics = %#v, want execution", parent.Tactics)
	}
}

func TestImportSTIXRejectsEmptyCatalog(t *testing.T) {
	database := openTestDatabase(t)
	if _, err := ImportSTIX(database, strings.NewReader(`{"objects":[]}`), "v-test"); err == nil {
		t.Fatal("ImportSTIX() error = nil, want empty catalog error")
	}

	var count int64
	if err := database.Model(&models.DatasetImport{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("import records = %d, want 0", count)
	}
}

func openTestDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	database, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{TranslateError: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureSchema(database); err != nil {
		t.Fatal(err)
	}
	sqlDatabase, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDatabase.Close() })
	return database
}
