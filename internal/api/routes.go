package api

import (
	"net/http"
	"strconv"
	"ttp-tool-mapper/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Handler struct {
	DB *gorm.DB
}

type ProcedureInput struct {
	ToolID         uint   `json:"tool_id"`
	TechniqueID    uint   `json:"technique_id"`
	Summary        string `json:"summary"`
	CommandExample string `json:"command_example"`
	Notes          string `json:"notes"`
}

type DetectionInput struct {
	TechniqueID uint   `json:"technique_id"`
	Type        string `json:"type"`
	Content     string `json:"content"`
	Source      string `json:"source"`
}

func RegisterRoutes(router *gin.Engine, database *gorm.DB) {
	handler := &Handler{DB: database}
	api := router.Group("/api/v1")
	api.GET("/health", handler.Health)
	api.GET("/techniques", handler.ListTechniques)
	api.GET("/techniques/:id", handler.GetTechnique)
	api.GET("/tools", handler.ListTools)
	api.GET("/tools/:id", handler.GetTool)
	api.GET("/mappings", handler.ListMappings)
	api.POST("/procedures", handler.CreateProcedure)
	api.POST("/detections", handler.CreateDetection)
}

func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) ListTechniques(c *gin.Context) {
	var techniques []models.Technique
	if err := h.DB.Preload("Procedures").Preload("Detections").Find(&techniques).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"techniques": techniques})
}

func (h *Handler) GetTechnique(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid technique id"})
		return
	}

	var technique models.Technique
	if err := h.DB.Preload("Procedures").Preload("Detections").First(&technique, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "technique not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"technique": technique})
}

func (h *Handler) ListTools(c *gin.Context) {
	var tools []models.Tool
	if err := h.DB.Preload("Procedures").Find(&tools).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tools": tools})
}

func (h *Handler) GetTool(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tool id"})
		return
	}

	var tool models.Tool
	if err := h.DB.Preload("Procedures").First(&tool, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tool not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tool": tool})
}

func (h *Handler) ListMappings(c *gin.Context) {
	var procedures []models.Procedure
	query := h.DB.Preload("Tool").Preload("Technique")

	if techniqueID := c.Query("technique"); techniqueID != "" {
		parsedID, err := strconv.Atoi(techniqueID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid technique query parameter"})
			return
		}
		query = query.Where("technique_id = ?", parsedID)
	}

	if toolID := c.Query("tool"); toolID != "" {
		parsedID, err := strconv.Atoi(toolID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tool query parameter"})
			return
		}
		query = query.Where("tool_id = ?", parsedID)
	}

	if err := query.Find(&procedures).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"mappings": procedures})
}

func (h *Handler) CreateProcedure(c *gin.Context) {
	var input ProcedureInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid procedure payload"})
		return
	}

	procedure := models.Procedure{
		ToolID:         input.ToolID,
		TechniqueID:    input.TechniqueID,
		Summary:        input.Summary,
		CommandExample: input.CommandExample,
		Notes:          input.Notes,
	}
	if err := h.DB.Create(&procedure).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"procedure": procedure})
}

func (h *Handler) CreateDetection(c *gin.Context) {
	var input DetectionInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid detection payload"})
		return
	}

	detection := models.Detection{
		TechniqueID: input.TechniqueID,
		Type:        input.Type,
		Content:     input.Content,
		Source:      input.Source,
	}
	if err := h.DB.Create(&detection).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"detection": detection})
}
