package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

func main() {
	dbPath := "security_rules.db"
	if len(os.Args) > 1 {
		dbPath = os.Args[1]
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer db.Close()

	var total int
	db.QueryRow("SELECT COUNT(*) FROM security_rules").Scan(&total)
	fmt.Printf("Total rules: %d\n\n", total)

	fmt.Println("=== BY SEVERITY ===")
	rows, _ := db.Query("SELECT severity, COUNT(*) as cnt FROM security_rules GROUP BY severity ORDER BY cnt DESC")
	for rows.Next() {
		var severity string
		var count int
		rows.Scan(&severity, &count)
		fmt.Printf("  %-12s %d\n", severity, count)
	}
	rows.Close()

	fmt.Println("\n=== BY SOURCE ===")
	rows, _ = db.Query("SELECT source, COUNT(*) as cnt FROM security_rules GROUP BY source ORDER BY cnt DESC")
	for rows.Next() {
		var source string
		var count int
		rows.Scan(&source, &count)
		fmt.Printf("  %-20s %d\n", source, count)
	}
	rows.Close()

	fmt.Println("\n=== BY CATEGORY (top 20) ===")
	rows, _ = db.Query("SELECT category, COUNT(*) as cnt FROM security_rules GROUP BY category ORDER BY cnt DESC LIMIT 20")
	for rows.Next() {
		var category string
		var count int
		rows.Scan(&category, &count)
		fmt.Printf("  %-35s %d\n", category, count)
	}
	rows.Close()

	fmt.Println("\n=== DUPLICATE TITLES (same title, different IDs) ===")
	rows, _ = db.Query("SELECT title, COUNT(*) as cnt FROM security_rules GROUP BY title HAVING cnt > 1 ORDER BY cnt DESC LIMIT 20")
	for rows.Next() {
		var title string
		var count int
		rows.Scan(&title, &count)
		fmt.Printf("  [%dx] %s\n", count, title)
	}
	rows.Close()

	fmt.Println("\n=== DUPLICATE CHECK_INSTRUCTIONS (identical instruction text) ===")
	var dupInstructions int
	db.QueryRow("SELECT COUNT(*) FROM (SELECT check_instruction, COUNT(*) as cnt FROM security_rules WHERE check_instruction != '' GROUP BY check_instruction HAVING cnt > 1)").Scan(&dupInstructions)
	fmt.Printf("  Groups with duplicate check_instructions: %d\n", dupInstructions)

	var dupInstructionRows int
	db.QueryRow("SELECT SUM(cnt) - COUNT(*) FROM (SELECT check_instruction, COUNT(*) as cnt FROM security_rules WHERE check_instruction != '' GROUP BY check_instruction HAVING cnt > 1)").Scan(&dupInstructionRows)
	fmt.Printf("  Excess duplicates (removable): %d\n", dupInstructionRows)

	fmt.Println("\n=== RULES WITH EMPTY CHECK_INSTRUCTION ===")
	var emptyCheck int
	db.QueryRow("SELECT COUNT(*) FROM security_rules WHERE check_instruction = '' OR check_instruction IS NULL").Scan(&emptyCheck)
	fmt.Printf("  Rules without check_instruction: %d\n", emptyCheck)

	fmt.Println("\n=== RULES WITH 'all' IN LANGUAGES (very generic) ===")
	var allLang int
	db.QueryRow(`SELECT COUNT(*) FROM security_rules WHERE languages LIKE '%"all"%'`).Scan(&allLang)
	fmt.Printf("  Rules with language='all': %d\n", allLang)

	fmt.Println("\n=== NEAR-DUPLICATE DETECTION (same title+source) ===")
	var sameTitleSource int
	db.QueryRow("SELECT COUNT(*) FROM (SELECT title, source, COUNT(*) as cnt FROM security_rules GROUP BY title, source HAVING cnt > 1)").Scan(&sameTitleSource)
	fmt.Printf("  Same title + source: %d groups\n", sameTitleSource)

	fmt.Println("\n=== AUDIT TYPE TIERS ===")

	var codeDefault int
	db.QueryRow(`SELECT COUNT(*) FROM security_rules WHERE source IN ('cwe','capec','mitre_attack') AND category != 'supply_chain' AND NOT (source = 'mitre_attack' AND category = 'other')`).Scan(&codeDefault)
	fmt.Printf("  code (default):      %d rules (CAPEC+CWE+code-relevant MITRE)\n", codeDefault)

	var infra int
	db.QueryRow(`SELECT COUNT(*) FROM security_rules WHERE source IN ('mitre_attack','cisa_kev') AND category != 'supply_chain'`).Scan(&infra)
	fmt.Printf("  infrastructure:      %d rules (all MITRE + CISA KEV)\n", infra)

	var extended int
	db.QueryRow(`SELECT COUNT(*) FROM security_rules WHERE source IN ('cwe','capec','mitre_attack','nuclei') AND category != 'supply_chain'`).Scan(&extended)
	fmt.Printf("  extended:            %d rules (code + nuclei templates)\n", extended)

	var full int
	db.QueryRow(`SELECT COUNT(*) FROM security_rules WHERE category != 'supply_chain'`).Scan(&full)
	fmt.Printf("  full:                %d rules (all non-dependency)\n", full)

	var dependency int
	db.QueryRow(`SELECT COUNT(*) FROM security_rules WHERE category = 'supply_chain'`).Scan(&dependency)
	fmt.Printf("  dependency:          %d rules (supply chain/package versions)\n", dependency)

	fmt.Println("\n  Code audit breakdown by source:")
	rows, _ = db.Query(`SELECT source, COUNT(*) FROM security_rules WHERE source IN ('cwe','capec','mitre_attack') AND category != 'supply_chain' AND NOT (source = 'mitre_attack' AND category = 'other') GROUP BY source ORDER BY COUNT(*) DESC`)
	for rows.Next() {
		var src string
		var cnt int
		rows.Scan(&src, &cnt)
		fmt.Printf("    %-20s %d\n", src, cnt)
	}
	rows.Close()

	fmt.Println("\n  Code audit breakdown by category:")
	rows, _ = db.Query(`SELECT category, COUNT(*) FROM security_rules WHERE source IN ('cwe','capec','mitre_attack') AND category != 'supply_chain' AND NOT (source = 'mitre_attack' AND category = 'other') GROUP BY category ORDER BY COUNT(*) DESC`)
	for rows.Next() {
		var cat string
		var cnt int
		rows.Scan(&cat, &cnt)
		fmt.Printf("    %-30s %d\n", cat, cnt)
	}
	rows.Close()
}
