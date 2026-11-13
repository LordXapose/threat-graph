package models

import "time"

type Technique struct {
	ID          uint        `json:"id" gorm:"primaryKey"`
	ATTACKID    string      `json:"attack_id" gorm:"column:attack_id;uniqueIndex;not null"`
	Name        string      `json:"name" gorm:"not null"`
	Description string      `json:"description"`
	Deprecated  bool        `json:"deprecated" gorm:"not null;default:false"`
	Revoked     bool        `json:"revoked" gorm:"not null;default:false"`
	ParentID    *uint       `json:"parent_id"`
	Parent      *Technique  `json:"parent,omitempty" gorm:"foreignKey:ParentID"`
	Tactics     []Tactic    `json:"tactics,omitempty" gorm:"many2many:technique_tactics"`
	Platforms   []Platform  `json:"platforms,omitempty" gorm:"many2many:technique_platforms"`
	Procedures  []Procedure `json:"procedures,omitempty" gorm:"foreignKey:TechniqueID"`
	Detections  []Detection `json:"detections,omitempty" gorm:"foreignKey:TechniqueID"`
}

type Tactic struct {
	ID        uint   `json:"id" gorm:"primaryKey"`
	Name      string `json:"name" gorm:"not null"`
	ShortName string `json:"short_name" gorm:"uniqueIndex;not null"`
}

type Platform struct {
	ID   uint   `json:"id" gorm:"primaryKey"`
	Name string `json:"name" gorm:"uniqueIndex;not null"`
}

type Tool struct {
	ID          uint        `json:"id" gorm:"primaryKey"`
	Name        string      `json:"name" gorm:"uniqueIndex;not null"`
	Category    string      `json:"category"`
	Vendor      string      `json:"vendor"`
	Description string      `json:"description"`
	Procedures  []Procedure `json:"procedures,omitempty" gorm:"foreignKey:ToolID"`
}

type Procedure struct {
	ID             uint       `json:"id" gorm:"primaryKey"`
	ToolID         uint       `json:"tool_id" gorm:"not null;index"`
	TechniqueID    uint       `json:"technique_id" gorm:"not null;index"`
	Summary        string     `json:"summary" gorm:"not null"`
	CommandExample string     `json:"command_example,omitempty"`
	Notes          string     `json:"notes,omitempty"`
	Source         string     `json:"source" gorm:"not null"`
	Confidence     float64    `json:"confidence" gorm:"not null;default:0"`
	ReviewedAt     *time.Time `json:"reviewed_at,omitempty"`
	Tool           Tool       `json:"tool,omitempty" gorm:"foreignKey:ToolID"`
	Technique      Technique  `json:"technique,omitempty" gorm:"foreignKey:TechniqueID"`
}

type Detection struct {
	ID          uint       `json:"id" gorm:"primaryKey"`
	TechniqueID uint       `json:"technique_id" gorm:"not null;index"`
	Type        string     `json:"type" gorm:"not null"`
	Content     string     `json:"content" gorm:"not null"`
	Source      string     `json:"source" gorm:"not null"`
	Confidence  float64    `json:"confidence" gorm:"not null;default:0"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
	Technique   Technique  `json:"technique,omitempty" gorm:"foreignKey:TechniqueID"`
}

type DatasetImport struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Dataset     string    `json:"dataset" gorm:"uniqueIndex:idx_dataset_version;not null"`
	Version     string    `json:"version" gorm:"uniqueIndex:idx_dataset_version;not null"`
	SHA256      string    `json:"sha256" gorm:"not null"`
	ObjectCount int       `json:"object_count" gorm:"not null"`
	ImportedAt  time.Time `json:"imported_at" gorm:"not null"`
}
