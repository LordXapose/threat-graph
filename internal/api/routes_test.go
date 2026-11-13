package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"ttp-tool-mapper/internal/db"
	"ttp-tool-mapper/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestWriteValidationAndAttackIDLookup(t *testing.T) {
	router, database := testRouter(t, Config{WriteToken: "test-token", RequestsPerMinute: 60})
	technique := models.Technique{ATTACKID: "T1000", Name: "Example technique"}
	if err := database.Create(&technique).Error; err != nil {
		t.Fatal(err)
	}

	response := request(router, http.MethodPost, "/api/v1/tools", `{"name":"Example"}`, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized tool creation status = %d, want %d", response.Code, http.StatusUnauthorized)
	}

	response = request(router, http.MethodPost, "/api/v1/tools", `{"name":""}`, "test-token")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("empty tool name status = %d, want %d", response.Code, http.StatusBadRequest)
	}

	response = request(router, http.MethodPost, "/api/v1/tools", `{"name":"Example"}`, "test-token")
	if response.Code != http.StatusCreated {
		t.Fatalf("tool creation status = %d, want %d; body: %s", response.Code, http.StatusCreated, response.Body)
	}
	var toolResponse struct {
		Data models.Tool `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &toolResponse); err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(ProcedureInput{
		ToolID:      toolResponse.Data.ID,
		TechniqueID: technique.ID,
		Summary:     "Documented lab mapping",
		Source:      "internal research",
		Confidence:  1.1,
	})
	if err != nil {
		t.Fatal(err)
	}
	response = request(router, http.MethodPost, "/api/v1/procedures", string(payload), "test-token")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid confidence status = %d, want %d", response.Code, http.StatusBadRequest)
	}

	payload, err = json.Marshal(ProcedureInput{
		ToolID:      toolResponse.Data.ID,
		TechniqueID: technique.ID,
		Summary:     "Documented lab mapping",
		Source:      "internal research",
		Confidence:  0.8,
	})
	if err != nil {
		t.Fatal(err)
	}
	response = request(router, http.MethodPost, "/api/v1/procedures", string(payload), "test-token")
	if response.Code != http.StatusCreated {
		t.Fatalf("valid procedure creation status = %d, want %d; body: %s", response.Code, http.StatusCreated, response.Body)
	}
	response = request(router, http.MethodGet, "/api/v1/mappings?technique=T1000", "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("ATT&CK ID mapping filter status = %d, want %d", response.Code, http.StatusOK)
	}

	response = request(router, http.MethodGet, "/api/v1/techniques/T1000", "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("ATT&CK ID lookup status = %d, want %d", response.Code, http.StatusOK)
	}
	response = request(router, http.MethodGet, "/api/v1/techniques/1", "", "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("numeric technique lookup status = %d, want %d", response.Code, http.StatusNotFound)
	}
	response = request(router, http.MethodGet, "/api/v1/techniques?limit=0", "", "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid page size status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	response = request(router, http.MethodGet, "/api/v1/techniques?q=Example&tactic=not-a-tactic", "", "")
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"total":0`)) {
		t.Fatalf("combined search filters status/body = %d/%s, want zero results", response.Code, response.Body)
	}
}

func TestRateLimit(t *testing.T) {
	router, _ := testRouter(t, Config{WriteToken: "test-token", RequestsPerMinute: 1})
	for index, want := range []int{http.StatusOK, http.StatusTooManyRequests} {
		response := request(router, http.MethodGet, "/api/v1/health", "", "")
		if response.Code != want {
			t.Fatalf("request %d status = %d, want %d", index+1, response.Code, want)
		}
	}
}

func testRouter(t *testing.T, config Config) (*gin.Engine, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
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
	router := gin.New()
	RegisterRoutes(router, database, config)
	return router, database
}

func request(router http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	return response
}
