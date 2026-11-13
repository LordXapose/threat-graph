package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"ttp-tool-mapper/internal/attack"
	"ttp-tool-mapper/internal/db"
)

func main() {
	inputPath := flag.String("file", "", "path to an official ATT&CK STIX JSON bundle")
	version := flag.String("version", "", "ATT&CK dataset release version")
	databasePath := flag.String("db", "data/ttp_tool_mapper.db", "SQLite database path")
	flag.Parse()

	if *inputPath == "" || *version == "" {
		flag.Usage()
		log.Fatal("--file and --version are required")
	}

	input, err := os.Open(*inputPath)
	if err != nil {
		log.Fatalf("open STIX bundle: %v", err)
	}
	defer input.Close()

	database, err := db.Open(*databasePath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	if err := db.EnsureSchema(database); err != nil {
		log.Fatalf("migrate database: %v", err)
	}

	count, err := attack.ImportSTIX(database, input, *version)
	if err != nil {
		log.Fatalf("import ATT&CK data: %v", err)
	}
	fmt.Printf("Imported %d ATT&CK techniques from version %s into %s\n", count, *version, *databasePath)
}
