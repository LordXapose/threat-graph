# TTP Tool Mapper

A Go-based research API for mapping ATT&CK techniques to the tools, procedures, and detections that relate to them.

## Purpose

This project is a reusable security-research service for:

- red-team planning
- purple-team workflows
- detection engineering
- technique coverage tracking

## Features

- ATT&CK-style technique catalog
- tool registry
- procedure mapping
- detection mapping
- SQLite-backed storage for local development
- JSON API endpoints for lookup and insertion

## Quick start

```bash
go mod tidy
go run ./cmd/server
```

The API listens on port `8080`.

## API endpoints

- `GET /api/v1/health`
- `GET /api/v1/techniques`
- `GET /api/v1/techniques/:id`
- `GET /api/v1/tools`
- `GET /api/v1/tools/:id`
- `GET /api/v1/mappings?technique=1&tool=1`
- `POST /api/v1/procedures`
- `POST /api/v1/detections`

## Data model

- `Technique`
- `Tool`
- `Procedure`
- `Detection`

## Notes

This is a lab-oriented research project and should be used only in approved, controlled environments.
