package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/LordXapose/threat-graph/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	defaultPageSize = 20
	maxPageSize     = 100
	maxBodySize     = 1 << 20
)

type Config struct {
	WriteToken        string
	RequestsPerMinute int
}

type Handler struct {
	DB *gorm.DB
}

type ToolInput struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Vendor      string `json:"vendor"`
	Description string `json:"description"`
}

type ProcedureInput struct {
	ToolID         uint       `json:"tool_id"`
	TechniqueID    uint       `json:"technique_id"`
	Summary        string     `json:"summary"`
	CommandExample string     `json:"command_example"`
	Notes          string     `json:"notes"`
	Source         string     `json:"source"`
	Confidence     float64    `json:"confidence"`
	ReviewedAt     *time.Time `json:"reviewed_at"`
}

type DetectionInput struct {
	TechniqueID uint       `json:"technique_id"`
	Type        string     `json:"type"`
	Content     string     `json:"content"`
	Source      string     `json:"source"`
	Confidence  float64    `json:"confidence"`
	ReviewedAt  *time.Time `json:"reviewed_at"`
}

type pageRequest struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func RegisterRoutes(router *gin.Engine, database *gorm.DB, config Config) {
	handler := &Handler{DB: database}
	router.Use(rateLimit(config.RequestsPerMinute))

	api := router.Group("/api/v1")
	api.GET("/health", handler.Health)
	api.GET("/techniques", handler.ListTechniques)
	api.GET("/techniques/:attack_id", handler.GetTechnique)
	api.GET("/tools", handler.ListTools)
	api.GET("/tools/:id", handler.GetTool)
	api.GET("/mappings", handler.ListMappings)
	api.GET("/imports", handler.ListImports)

	writes := api.Group("")
	writes.Use(writeAuth(config.WriteToken), bodyLimit(maxBodySize))
	writes.POST("/tools", handler.CreateTool)
	writes.POST("/procedures", handler.CreateProcedure)
	writes.POST("/detections", handler.CreateDetection)
}

func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"status": "ok"}})
}

func (h *Handler) ListTechniques(c *gin.Context) {
	page, ok := parsePage(c)
	if !ok {
		return
	}

	query := h.DB.Model(&models.Technique{})
	if name := strings.TrimSpace(c.Query("q")); name != "" {
		query = query.Where("(name LIKE ? OR attack_id LIKE ?)", "%"+name+"%", "%"+name+"%")
	}
	if tactic := strings.TrimSpace(c.Query("tactic")); tactic != "" {
		subquery := h.DB.Table("technique_tactics").
			Select("technique_id").
			Joins("JOIN tactics ON tactics.id = technique_tactics.tactic_id").
			Where("tactics.short_name = ?", tactic)
		query = query.Where("id IN (?)", subquery)
	}
	if platform := strings.TrimSpace(c.Query("platform")); platform != "" {
		subquery := h.DB.Table("technique_platforms").
			Select("technique_id").
			Joins("JOIN platforms ON platforms.id = technique_platforms.platform_id").
			Where("platforms.name = ?", platform)
		query = query.Where("id IN (?)", subquery)
	}
	if value := c.Query("deprecated"); value != "" {
		deprecated, err := strconv.ParseBool(value)
		if err != nil {
			writeError(c, http.StatusBadRequest, "invalid_query", "deprecated must be true or false")
			return
		}
		query = query.Where("deprecated = ?", deprecated)
	}
	if value := c.Query("revoked"); value != "" {
		revoked, err := strconv.ParseBool(value)
		if err != nil {
			writeError(c, http.StatusBadRequest, "invalid_query", "revoked must be true or false")
			return
		}
		query = query.Where("revoked = ?", revoked)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.databaseError(c, err)
		return
	}
	var techniques []models.Technique
	if err := query.Preload("Tactics").Preload("Platforms").
		Order("attack_id").Limit(page.Limit).Offset(page.Offset).Find(&techniques).Error; err != nil {
		h.databaseError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": techniques, "page": pageResponse(page, total)})
}

func (h *Handler) GetTechnique(c *gin.Context) {
	attackID := strings.ToUpper(strings.TrimSpace(c.Param("attack_id")))
	var technique models.Technique
	err := h.DB.Preload("Parent").Preload("Tactics").Preload("Platforms").
		Preload("Procedures.Tool").Preload("Detections").
		Where("attack_id = ?", attackID).First(&technique).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		writeError(c, http.StatusNotFound, "not_found", "technique not found")
		return
	}
	if err != nil {
		h.databaseError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": technique})
}

func (h *Handler) ListTools(c *gin.Context) {
	page, ok := parsePage(c)
	if !ok {
		return
	}
	query := h.DB.Model(&models.Tool{})
	if name := strings.TrimSpace(c.Query("q")); name != "" {
		query = query.Where("name LIKE ?", "%"+name+"%")
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.databaseError(c, err)
		return
	}
	var tools []models.Tool
	if err := query.Order("name").Limit(page.Limit).Offset(page.Offset).Find(&tools).Error; err != nil {
		h.databaseError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": tools, "page": pageResponse(page, total)})
}

func (h *Handler) GetTool(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		writeError(c, http.StatusBadRequest, "invalid_id", "tool id must be a positive integer")
		return
	}
	var tool models.Tool
	err = h.DB.Preload("Procedures.Technique").First(&tool, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		writeError(c, http.StatusNotFound, "not_found", "tool not found")
		return
	}
	if err != nil {
		h.databaseError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": tool})
}

func (h *Handler) ListMappings(c *gin.Context) {
	page, ok := parsePage(c)
	if !ok {
		return
	}
	query := h.DB.Model(&models.Procedure{})
	if attackID := strings.TrimSpace(c.Query("technique")); attackID != "" {
		query = query.Where("technique_id IN (?)",
			h.DB.Model(&models.Technique{}).Select("id").Where("attack_id = ?", strings.ToUpper(attackID)))
	}
	if tool := strings.TrimSpace(c.Query("tool")); tool != "" {
		if id, err := strconv.ParseUint(tool, 10, 64); err == nil && id > 0 {
			query = query.Where("tool_id = ?", id)
		} else {
			query = query.Where("tool_id IN (?)",
				h.DB.Model(&models.Tool{}).Select("id").Where("name = ?", tool))
		}
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.databaseError(c, err)
		return
	}
	var procedures []models.Procedure
	if err := query.Preload("Tool").Preload("Technique.Tactics").Preload("Technique.Platforms").
		Order("id").Limit(page.Limit).Offset(page.Offset).Find(&procedures).Error; err != nil {
		h.databaseError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": procedures, "page": pageResponse(page, total)})
}

func (h *Handler) ListImports(c *gin.Context) {
	page, ok := parsePage(c)
	if !ok {
		return
	}
	var total int64
	if err := h.DB.Model(&models.DatasetImport{}).Count(&total).Error; err != nil {
		h.databaseError(c, err)
		return
	}
	var imports []models.DatasetImport
	if err := h.DB.Order("imported_at DESC").Limit(page.Limit).Offset(page.Offset).Find(&imports).Error; err != nil {
		h.databaseError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": imports, "page": pageResponse(page, total)})
}

func (h *Handler) CreateTool(c *gin.Context) {
	var input ToolInput
	if err := decodeJSON(c, &input); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_payload", "invalid tool payload")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || len(input.Name) > 200 {
		writeError(c, http.StatusBadRequest, "invalid_payload", "name is required and must be at most 200 bytes")
		return
	}

	tool := models.Tool{
		Name:        input.Name,
		Category:    strings.TrimSpace(input.Category),
		Vendor:      strings.TrimSpace(input.Vendor),
		Description: strings.TrimSpace(input.Description),
	}
	result := h.DB.Create(&tool)
	if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
		writeError(c, http.StatusConflict, "conflict", "a tool with that name already exists")
		return
	}
	if result.Error != nil {
		h.databaseError(c, result.Error)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": tool})
}

func (h *Handler) CreateProcedure(c *gin.Context) {
	var input ProcedureInput
	if err := decodeJSON(c, &input); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_payload", "invalid procedure payload")
		return
	}
	input.Summary = strings.TrimSpace(input.Summary)
	input.Source = strings.TrimSpace(input.Source)
	if input.ToolID == 0 || input.TechniqueID == 0 || input.Summary == "" || input.Source == "" ||
		len(input.Summary) > 2000 || len(input.Source) > 300 || len(input.CommandExample) > 4096 ||
		len(input.Notes) > 8000 || !validConfidence(input.Confidence) {
		writeError(c, http.StatusBadRequest, "invalid_payload", "procedure fields are missing or outside allowed limits")
		return
	}
	toolExists, err := h.toolExists(input.ToolID)
	if err != nil {
		h.databaseError(c, err)
		return
	}
	if !toolExists {
		writeError(c, http.StatusBadRequest, "invalid_reference", "tool_id does not identify an existing tool")
		return
	}
	techniqueExists, err := h.techniqueExists(input.TechniqueID)
	if err != nil {
		h.databaseError(c, err)
		return
	}
	if !techniqueExists {
		writeError(c, http.StatusBadRequest, "invalid_reference", "technique_id does not identify an existing technique")
		return
	}

	procedure := models.Procedure{
		ToolID:         input.ToolID,
		TechniqueID:    input.TechniqueID,
		Summary:        input.Summary,
		CommandExample: strings.TrimSpace(input.CommandExample),
		Notes:          strings.TrimSpace(input.Notes),
		Source:         input.Source,
		Confidence:     input.Confidence,
		ReviewedAt:     input.ReviewedAt,
	}
	if err := h.DB.Create(&procedure).Error; err != nil {
		h.databaseError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": procedure})
}

func (h *Handler) CreateDetection(c *gin.Context) {
	var input DetectionInput
	if err := decodeJSON(c, &input); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_payload", "invalid detection payload")
		return
	}
	input.Type = strings.TrimSpace(input.Type)
	input.Source = strings.TrimSpace(input.Source)
	input.Content = strings.TrimSpace(input.Content)
	if input.TechniqueID == 0 || input.Type == "" || input.Source == "" || input.Content == "" ||
		len(input.Type) > 100 || len(input.Source) > 300 || len(input.Content) > 65536 ||
		!validConfidence(input.Confidence) {
		writeError(c, http.StatusBadRequest, "invalid_payload", "detection fields are missing or outside allowed limits")
		return
	}
	techniqueExists, err := h.techniqueExists(input.TechniqueID)
	if err != nil {
		h.databaseError(c, err)
		return
	}
	if !techniqueExists {
		writeError(c, http.StatusBadRequest, "invalid_reference", "technique_id does not identify an existing technique")
		return
	}

	detection := models.Detection{
		TechniqueID: input.TechniqueID,
		Type:        input.Type,
		Content:     input.Content,
		Source:      input.Source,
		Confidence:  input.Confidence,
		ReviewedAt:  input.ReviewedAt,
	}
	if err := h.DB.Create(&detection).Error; err != nil {
		h.databaseError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": detection})
}

func (h *Handler) toolExists(id uint) (bool, error) {
	var count int64
	err := h.DB.Model(&models.Tool{}).Where("id = ?", id).Count(&count).Error
	return count == 1, err
}

func (h *Handler) techniqueExists(id uint) (bool, error) {
	var count int64
	err := h.DB.Model(&models.Technique{}).Where("id = ?", id).Count(&count).Error
	return count == 1, err
}

func (h *Handler) databaseError(c *gin.Context, err error) {
	_ = c.Error(err)
	writeError(c, http.StatusInternalServerError, "internal_error", "an internal error occurred")
}

func decodeJSON(c *gin.Context, destination any) error {
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("request body must contain a single JSON value")
	}
	return nil
}

func parsePage(c *gin.Context) (pageRequest, bool) {
	page := pageRequest{Limit: defaultPageSize}
	if value := c.Query("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit < 1 || limit > maxPageSize {
			writeError(c, http.StatusBadRequest, "invalid_query", "limit must be between 1 and 100")
			return pageRequest{}, false
		}
		page.Limit = limit
	}
	if value := c.Query("offset"); value != "" {
		offset, err := strconv.Atoi(value)
		if err != nil || offset < 0 {
			writeError(c, http.StatusBadRequest, "invalid_query", "offset must be a non-negative integer")
			return pageRequest{}, false
		}
		page.Offset = offset
	}
	return page, true
}

func pageResponse(page pageRequest, total int64) gin.H {
	return gin.H{"limit": page.Limit, "offset": page.Offset, "total": total}
}

func validConfidence(confidence float64) bool {
	return confidence >= 0 && confidence <= 1
}

func writeError(c *gin.Context, status int, code, message string) {
	c.JSON(status, errorBody{Error: errorDetail{Code: code, Message: message}})
}
