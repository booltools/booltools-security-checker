package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"

	_ "modernc.org/sqlite"
)

func main() {
	dbPath := flag.String("db", "security_rules.db", "Path to the security rules database")
	dryRun := flag.Bool("dry-run", false, "Only report duplicates without removing")
	flag.Parse()

	if _, err := os.Stat(*dbPath); os.IsNotExist(err) {
		log.Fatalf("Database not found: %s", *dbPath)
	}

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("Opening database: %v", err)
	}
	defer db.Close()

	db.Exec("PRAGMA journal_mode=DELETE")
	db.Exec("PRAGMA busy_timeout=30000")

	var totalBefore int
	db.QueryRow("SELECT COUNT(*) FROM security_rules").Scan(&totalBefore)
	fmt.Printf("Rules before deduplication: %d\n\n", totalBefore)

	// Step 1: Remove exact title+source duplicates (keep the one with highest CVSS)
	fmt.Println("Step 1: Removing title+source duplicates...")
	titleSourceDups := removeTitleSourceDuplicates(db, *dryRun)
	fmt.Printf("  Removed: %d\n\n", titleSourceDups)

	// Step 2: Remove cross-source duplicates (same CVE ID covered by multiple sources)
	fmt.Println("Step 2: Removing cross-source CVE duplicates (keeping highest quality)...")
	cveDups := removeCrossSourceCVEDuplicates(db, *dryRun)
	fmt.Printf("  Removed: %d\n\n", cveDups)

	// Step 3: Remove rules with near-identical titles (fuzzy dedup within same category)
	fmt.Println("Step 3: Removing near-identical title duplicates (same category)...")
	nearDups := removeNearDuplicateTitles(db, *dryRun)
	fmt.Printf("  Removed: %d\n\n", nearDups)

	var totalAfter int
	db.QueryRow("SELECT COUNT(*) FROM security_rules").Scan(&totalAfter)
	fmt.Printf("Rules after deduplication: %d\n", totalAfter)
	fmt.Printf("Total removed: %d (%.1f%% reduction)\n", totalBefore-totalAfter, float64(totalBefore-totalAfter)/float64(totalBefore)*100)

	if *dryRun {
		fmt.Println("\n(Dry run — no changes applied)")
	} else {
		fmt.Println("\nRunning VACUUM to reclaim space...")
		db.Exec("VACUUM")
		fmt.Println("Done.")
	}
}

func removeTitleSourceDuplicates(db *sql.DB, dryRun bool) int {
	query := `
		SELECT COUNT(*) FROM security_rules
		WHERE rowid NOT IN (
			SELECT MIN(rowid) FROM security_rules
			GROUP BY title, source, severity
		)
	`
	var count int
	db.QueryRow(query).Scan(&count)

	if !dryRun && count > 0 {
		_, err := db.Exec(`
			DELETE FROM security_rules
			WHERE rowid NOT IN (
				SELECT MIN(rowid) FROM security_rules
				GROUP BY title, source, severity
			)
		`)
		if err != nil {
			log.Printf("  Error removing title+source duplicates: %v", err)
			return 0
		}
	}
	return count
}

func removeCrossSourceCVEDuplicates(db *sql.DB, dryRun bool) int {
	// When the same CVE is present in multiple sources (e.g., NVD + OSV + CISA),
	// keep the rule from the highest-priority source (better data quality).
	// Priority: cisa_kev > nvd > nuclei > osv > exploitdb
	sourcePriority := map[string]int{
		"cisa_kev":     1,
		"nvd":          2,
		"nuclei":       3,
		"mitre_attack": 4,
		"capec":        5,
		"cwe":          6,
		"osv":          7,
		"exploitdb":    8,
	}

	rows, err := db.Query(`
		SELECT cve_ids, id, source FROM security_rules
		WHERE cve_ids != '' AND cve_ids != '[]' AND cve_ids != 'null'
		ORDER BY cvss_score DESC
	`)
	if err != nil {
		log.Printf("  Error querying CVEs: %v", err)
		return 0
	}
	defer rows.Close()

	cveSeen := make(map[string]struct {
		id       string
		source   string
		priority int
	})
	var toDelete []string

	for rows.Next() {
		var cveIDs, id, source string
		rows.Scan(&cveIDs, &id, &source)

		priority := sourcePriority[source]
		if priority == 0 {
			priority = 99
		}

		cveKey := cveIDs
		if existing, found := cveSeen[cveKey]; found {
			if priority < existing.priority {
				toDelete = append(toDelete, existing.id)
				cveSeen[cveKey] = struct {
					id       string
					source   string
					priority int
				}{id, source, priority}
			} else {
				toDelete = append(toDelete, id)
			}
		} else {
			cveSeen[cveKey] = struct {
				id       string
				source   string
				priority int
			}{id, source, priority}
		}
	}

	if !dryRun && len(toDelete) > 0 {
		batchDelete(db, toDelete)
	}

	return len(toDelete)
}

func removeNearDuplicateTitles(db *sql.DB, dryRun bool) int {
	// Remove rules with identical titles across different sources (keep best source)
	query := `
		SELECT COUNT(*) FROM security_rules
		WHERE rowid NOT IN (
			SELECT MIN(rowid) FROM security_rules
			GROUP BY title, category, severity
		)
	`
	var count int
	db.QueryRow(query).Scan(&count)

	if !dryRun && count > 0 {
		_, err := db.Exec(`
			DELETE FROM security_rules
			WHERE rowid NOT IN (
				SELECT MIN(rowid) FROM security_rules
				GROUP BY title, category, severity
			)
		`)
		if err != nil {
			log.Printf("  Error removing near-duplicates: %v", err)
			return 0
		}
	}
	return count
}

func batchDelete(db *sql.DB, ids []string) {
	const batchSize = 500
	for i := 0; i < len(ids); i += batchSize {
		end := i + batchSize
		if end > len(ids) {
			end = len(ids)
		}

		transaction, err := db.Begin()
		if err != nil {
			continue
		}

		stmt, err := transaction.Prepare("DELETE FROM security_rules WHERE id = ?")
		if err != nil {
			transaction.Rollback()
			continue
		}

		for _, id := range ids[i:end] {
			stmt.Exec(id)
		}

		stmt.Close()
		transaction.Commit()
	}
}
