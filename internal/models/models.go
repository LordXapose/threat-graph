package models

type Technique struct {
	ID          uint   `gorm:"primaryKey"`
	ATTACKID    string `gorm:"uniqueIndex;not null"`
	Name        string `gorm:"not null"`
	Tactic      string `gorm:"not null"`
	Description string
	Platform    string
	ParentID    *uint
	Parent      *Technique `gorm:"foreignKey:ParentID"`
	Procedures  []Procedure `gorm:"foreignKey:TechniqueID"`
	Detections  []Detection `gorm:"foreignKey:TechniqueID"`
}

type Tool struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"uniqueIndex;not null"`
	Category    string
	Vendor      string
	Description string
	Procedures  []Procedure `gorm:"foreignKey:ToolID"`
}

type Procedure struct {
	ID             uint      `gorm:"primaryKey"`
	ToolID         uint      `gorm:"not null"`
	TechniqueID    uint      `gorm:"not null"`
	Summary        string    `gorm:"not null"`
	CommandExample string
	Notes          string
	Tool           Tool       `gorm:"foreignKey:ToolID"`
	Technique      Technique `gorm:"foreignKey:TechniqueID"`
}

type Detection struct {
	ID          uint      `gorm:"primaryKey"`
	TechniqueID uint      `gorm:"not null"`
	Type        string    `gorm:"not null"`
	Content     string    `gorm:"not null"`
	Source      string
	Technique   Technique `gorm:"foreignKey:TechniqueID"`
}
