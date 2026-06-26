package normalizer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	_ "modernc.org/sqlite"
)

type Database struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewDatabase(dbPath string, logger *slog.Logger) (*Database, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database %s: %w", dbPath, err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if _, err := db.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting journal mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting synchronous: %w", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=30000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting busy_timeout: %w", err)
	}

	if _, err := db.Exec(SchemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}

	return &Database{db: db, logger: logger}, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) InsertBatch(rules []SecurityRule) error {
	transaction, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer transaction.Rollback()

	statement, err := transaction.Prepare(`
		INSERT OR REPLACE INTO security_rules (
			id, source, category, severity, title, description, remediation, check_instruction,
			languages, frameworks, platforms, applies_to,
			cvss_score, epss_score, is_kev,
			references_json, cve_ids, cwe_ids, published_at, updated_at, tags
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("preparing insert statement: %w", err)
	}
	defer statement.Close()

	for _, rule := range rules {
		languages := marshalJSON(rule.Languages)
		frameworks := marshalJSON(rule.Frameworks)
		platforms := marshalJSON(rule.Platforms)
		references := marshalJSON(rule.References)
		cveIDs := marshalJSON(rule.CVEIDs)
		cweIDs := marshalJSON(rule.CWEIDs)
		tags := marshalJSON(rule.Tags)

		_, err := statement.Exec(
			rule.ID, rule.Source, rule.Category, rule.Severity,
			rule.Title, rule.Description, rule.Remediation, rule.CheckInstruction,
			languages, frameworks, platforms, rule.AppliesTo,
			rule.CVSSScore, rule.EPSSScore, rule.IsKEV,
			references, cveIDs, cweIDs, rule.PublishedAt, rule.UpdatedAt, tags,
		)
		if err != nil {
			d.logger.Warn("failed to insert rule", "id", rule.ID, "error", err)
		}
	}

	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

func (d *Database) Count() (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM security_rules").Scan(&count)
	return count, err
}

func (d *Database) CountBySource() (map[string]int, error) {
	rows, err := d.db.Query("SELECT source, COUNT(*) FROM security_rules GROUP BY source")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var source string
		var count int
		if err := rows.Scan(&source, &count); err != nil {
			return nil, err
		}
		counts[source] = count
	}
	return counts, rows.Err()
}

type QueryFilter struct {
	Languages         []string
	Frameworks        []string
	Platforms         []string
	Sources           []string
	AppliesTo         string
	Severity          string
	MinSeverity       string
	Category          string
	ExcludeCategories []string
	ExcludeSourceCategories map[string][]string // source -> categories to exclude from that source
	IsKEV             *bool
	MinCVSS           float64
	Limit             int
	Offset            int
}

func severitiesAtOrAbove(minSeverity string) []string {
	order := []string{"critical", "high", "medium", "low", "info"}
	for i, severity := range order {
		if severity == minSeverity {
			return order[:i+1]
		}
	}
	return order
}

func (d *Database) QueryRules(filter QueryFilter) ([]SecurityRule, error) {
	query := "SELECT id, source, category, severity, title, description, remediation, check_instruction, languages, frameworks, platforms, applies_to, cvss_score, epss_score, is_kev, references_json, cve_ids, cwe_ids, published_at, updated_at, tags FROM security_rules WHERE 1=1"
	var args []interface{}

	if filter.Severity != "" {
		query += " AND severity = ?"
		args = append(args, filter.Severity)
	}
	if filter.MinSeverity != "" {
		severities := severitiesAtOrAbove(filter.MinSeverity)
		placeholders := make([]string, len(severities))
		for i, sev := range severities {
			placeholders[i] = "?"
			args = append(args, sev)
		}
		query += " AND severity IN (" + strings.Join(placeholders, ",") + ")"
	}
	if len(filter.Sources) > 0 {
		placeholders := make([]string, len(filter.Sources))
		for i, src := range filter.Sources {
			placeholders[i] = "?"
			args = append(args, src)
		}
		query += " AND source IN (" + strings.Join(placeholders, ",") + ")"
	}
	if filter.Category != "" {
		query += " AND category = ?"
		args = append(args, filter.Category)
	}
	for _, excludedCategory := range filter.ExcludeCategories {
		query += " AND category != ?"
		args = append(args, excludedCategory)
	}
	for source, categories := range filter.ExcludeSourceCategories {
		for _, category := range categories {
			query += " AND NOT (source = ? AND category = ?)"
			args = append(args, source, category)
		}
	}
	if filter.AppliesTo != "" {
		query += " AND (applies_to = ? OR applies_to = 'all')"
		args = append(args, filter.AppliesTo)
	}
	if filter.IsKEV != nil && *filter.IsKEV {
		query += " AND is_kev = TRUE"
	}
	if filter.MinCVSS > 0 {
		query += " AND cvss_score >= ?"
		args = append(args, filter.MinCVSS)
	}

	for _, language := range filter.Languages {
		query += " AND (languages LIKE ? OR languages LIKE ?)"
		args = append(args, fmt.Sprintf(`%%"%s"%%`, language), `%"all"%`)
	}
	for _, framework := range filter.Frameworks {
		query += " AND (frameworks LIKE ? OR frameworks LIKE ?)"
		args = append(args, fmt.Sprintf(`%%"%s"%%`, framework), `%"all"%`)
	}
	for _, platform := range filter.Platforms {
		query += " AND (platforms LIKE ? OR platforms LIKE ?)"
		args = append(args, fmt.Sprintf(`%%"%s"%%`, platform), `%"all"%`)
	}

	query += " ORDER BY cvss_score DESC, epss_score DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying rules: %w", err)
	}
	defer rows.Close()

	return scanRules(rows)
}

func (d *Database) GetRuleByID(id string) (*SecurityRule, error) {
	row := d.db.QueryRow("SELECT id, source, category, severity, title, description, remediation, check_instruction, languages, frameworks, platforms, applies_to, cvss_score, epss_score, is_kev, references_json, cve_ids, cwe_ids, published_at, updated_at, tags FROM security_rules WHERE id = ?", id)
	return scanRule(row)
}

func (d *Database) SearchRules(searchQuery string, limit int) ([]SecurityRule, error) {
	words := strings.Fields(strings.ToLower(searchQuery))
	if len(words) == 0 {
		return nil, nil
	}

	searchFields := []string{"id", "title", "description", "tags", "cve_ids", "cwe_ids"}

	// Build a relevance score: each matching word in each field adds 1 point
	var scoreParts []string
	var args []interface{}

	for _, word := range words {
		pattern := "%" + word + "%"
		for _, field := range searchFields {
			scoreParts = append(scoreParts, fmt.Sprintf("(CASE WHEN LOWER(%s) LIKE ? THEN 1 ELSE 0 END)", field))
			args = append(args, pattern)
		}
	}

	scoreExpr := strings.Join(scoreParts, " + ")

	query := fmt.Sprintf(
		`SELECT id, source, category, severity, title, description, remediation, check_instruction, languages, frameworks, platforms, applies_to, cvss_score, epss_score, is_kev, references_json, cve_ids, cwe_ids, published_at, updated_at, tags FROM security_rules WHERE (%s) > 0 ORDER BY (%s) DESC, cvss_score DESC LIMIT ?`,
		scoreExpr, scoreExpr,
	)
	// Duplicate args for the WHERE and ORDER BY
	allArgs := make([]interface{}, 0, len(args)*2+1)
	allArgs = append(allArgs, args...)
	allArgs = append(allArgs, args...)
	allArgs = append(allArgs, limit)

	rows, err := d.db.Query(query, allArgs...)
	if err != nil {
		return nil, fmt.Errorf("searching rules: %w", err)
	}
	defer rows.Close()

	return scanRules(rows)
}

func (d *Database) CountFiltered(filter QueryFilter) (int, error) {
	query := "SELECT COUNT(*) FROM security_rules WHERE 1=1"
	var args []interface{}

	if filter.Severity != "" {
		query += " AND severity = ?"
		args = append(args, filter.Severity)
	}
	if filter.MinSeverity != "" {
		severities := severitiesAtOrAbove(filter.MinSeverity)
		placeholders := make([]string, len(severities))
		for i, sev := range severities {
			placeholders[i] = "?"
			args = append(args, sev)
		}
		query += " AND severity IN (" + strings.Join(placeholders, ",") + ")"
	}
	if len(filter.Sources) > 0 {
		placeholders := make([]string, len(filter.Sources))
		for i, src := range filter.Sources {
			placeholders[i] = "?"
			args = append(args, src)
		}
		query += " AND source IN (" + strings.Join(placeholders, ",") + ")"
	}
	if filter.Category != "" {
		query += " AND category = ?"
		args = append(args, filter.Category)
	}
	for _, excludedCategory := range filter.ExcludeCategories {
		query += " AND category != ?"
		args = append(args, excludedCategory)
	}
	for source, categories := range filter.ExcludeSourceCategories {
		for _, category := range categories {
			query += " AND NOT (source = ? AND category = ?)"
			args = append(args, source, category)
		}
	}
	if filter.AppliesTo != "" {
		query += " AND (applies_to = ? OR applies_to = 'all')"
		args = append(args, filter.AppliesTo)
	}
	if filter.MinCVSS > 0 {
		query += " AND cvss_score >= ?"
		args = append(args, filter.MinCVSS)
	}
	for _, language := range filter.Languages {
		query += " AND (languages LIKE ? OR languages LIKE ?)"
		args = append(args, fmt.Sprintf(`%%"%s"%%`, language), `%"all"%`)
	}

	var count int
	err := d.db.QueryRow(query, args...).Scan(&count)
	return count, err
}

func scanRules(rows *sql.Rows) ([]SecurityRule, error) {
	var rules []SecurityRule
	for rows.Next() {
		rule, err := scanRuleFromRows(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, *rule)
	}
	return rules, rows.Err()
}

func scanRuleFromRows(rows *sql.Rows) (*SecurityRule, error) {
	var rule SecurityRule
	var languages, frameworks, platforms, references, cveIDs, cweIDs, tags sql.NullString
	var remediation sql.NullString
	var cvss, epss sql.NullFloat64
	var publishedAt, updatedAt sql.NullString

	err := rows.Scan(
		&rule.ID, &rule.Source, &rule.Category, &rule.Severity,
		&rule.Title, &rule.Description, &remediation, &rule.CheckInstruction,
		&languages, &frameworks, &platforms, &rule.AppliesTo,
		&cvss, &epss, &rule.IsKEV,
		&references, &cveIDs, &cweIDs, &publishedAt, &updatedAt, &tags,
	)
	if err != nil {
		return nil, err
	}

	if remediation.Valid {
		rule.Remediation = remediation.String
	}
	if cvss.Valid {
		rule.CVSSScore = cvss.Float64
	}
	if epss.Valid {
		rule.EPSSScore = epss.Float64
	}
	if publishedAt.Valid {
		rule.PublishedAt = publishedAt.String
	}
	if updatedAt.Valid {
		rule.UpdatedAt = updatedAt.String
	}

	rule.Languages = unmarshalJSONArray(languages)
	rule.Frameworks = unmarshalJSONArray(frameworks)
	rule.Platforms = unmarshalJSONArray(platforms)
	rule.References = unmarshalJSONArray(references)
	rule.CVEIDs = unmarshalJSONArray(cveIDs)
	rule.CWEIDs = unmarshalJSONArray(cweIDs)
	rule.Tags = unmarshalJSONArray(tags)

	return &rule, nil
}

func scanRule(row *sql.Row) (*SecurityRule, error) {
	var rule SecurityRule
	var languages, frameworks, platforms, references, cveIDs, cweIDs, tags sql.NullString
	var remediation sql.NullString
	var cvss, epss sql.NullFloat64
	var publishedAt, updatedAt sql.NullString

	err := row.Scan(
		&rule.ID, &rule.Source, &rule.Category, &rule.Severity,
		&rule.Title, &rule.Description, &remediation, &rule.CheckInstruction,
		&languages, &frameworks, &platforms, &rule.AppliesTo,
		&cvss, &epss, &rule.IsKEV,
		&references, &cveIDs, &cweIDs, &publishedAt, &updatedAt, &tags,
	)
	if err != nil {
		return nil, err
	}

	if remediation.Valid {
		rule.Remediation = remediation.String
	}
	if cvss.Valid {
		rule.CVSSScore = cvss.Float64
	}
	if epss.Valid {
		rule.EPSSScore = epss.Float64
	}
	if publishedAt.Valid {
		rule.PublishedAt = publishedAt.String
	}
	if updatedAt.Valid {
		rule.UpdatedAt = updatedAt.String
	}

	rule.Languages = unmarshalJSONArray(languages)
	rule.Frameworks = unmarshalJSONArray(frameworks)
	rule.Platforms = unmarshalJSONArray(platforms)
	rule.References = unmarshalJSONArray(references)
	rule.CVEIDs = unmarshalJSONArray(cveIDs)
	rule.CWEIDs = unmarshalJSONArray(cweIDs)
	rule.Tags = unmarshalJSONArray(tags)

	return &rule, nil
}

func marshalJSON(data []string) string {
	if len(data) == 0 {
		return "[]"
	}
	bytes, _ := json.Marshal(data)
	return string(bytes)
}

func unmarshalJSONArray(value sql.NullString) []string {
	if !value.Valid || value.String == "" || value.String == "[]" {
		return nil
	}
	var result []string
	_ = json.Unmarshal([]byte(value.String), &result)
	return result
}
