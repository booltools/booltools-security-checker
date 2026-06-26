package normalizer

type SecurityRule struct {
	ID               string   `json:"id"`
	Source           string   `json:"source"`
	Category         string   `json:"category"`
	Severity         string   `json:"severity"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Remediation      string   `json:"remediation,omitempty"`
	CheckInstruction string   `json:"check_instruction"`
	Languages        []string `json:"languages"`
	Frameworks       []string `json:"frameworks"`
	Platforms        []string `json:"platforms"`
	AppliesTo        string   `json:"applies_to"`
	CVSSScore        float64  `json:"cvss_score,omitempty"`
	EPSSScore        float64  `json:"epss_score,omitempty"`
	IsKEV            bool     `json:"is_kev"`
	References       []string `json:"references,omitempty"`
	CVEIDs           []string `json:"cve_ids,omitempty"`
	CWEIDs           []string `json:"cwe_ids,omitempty"`
	PublishedAt      string   `json:"published_at,omitempty"`
	UpdatedAt        string   `json:"updated_at,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

const SchemaSQL = `
CREATE TABLE IF NOT EXISTS security_rules (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT,
    check_instruction TEXT NOT NULL,
    languages TEXT,
    frameworks TEXT,
    platforms TEXT,
    applies_to TEXT NOT NULL DEFAULT 'all',
    cvss_score REAL,
    epss_score REAL,
    is_kev BOOLEAN DEFAULT FALSE,
    references_json TEXT,
    cve_ids TEXT,
    cwe_ids TEXT,
    published_at TEXT,
    updated_at TEXT,
    tags TEXT
);

CREATE INDEX IF NOT EXISTS idx_rules_category ON security_rules(category);
CREATE INDEX IF NOT EXISTS idx_rules_severity ON security_rules(severity);
CREATE INDEX IF NOT EXISTS idx_rules_source ON security_rules(source);
CREATE INDEX IF NOT EXISTS idx_rules_applies_to ON security_rules(applies_to);
CREATE INDEX IF NOT EXISTS idx_rules_is_kev ON security_rules(is_kev);
CREATE INDEX IF NOT EXISTS idx_rules_cvss ON security_rules(cvss_score);
CREATE INDEX IF NOT EXISTS idx_rules_epss ON security_rules(epss_score);
`

const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

const (
	CategoryInjection            = "injection"
	CategoryMisconfiguration     = "misconfiguration"
	CategoryBrokenAccessControl  = "broken_access_control"
	CategoryCryptographicFailure = "cryptographic_failure"
	CategorySupplyChain          = "supply_chain"
	CategoryInsecureDesign       = "insecure_design"
	CategoryAuthFailure          = "authentication_failure"
	CategoryIntegrityFailure     = "integrity_failure"
	CategoryLoggingFailure       = "logging_failure"
	CategorySSRF                 = "ssrf"
	CategoryExposure             = "information_exposure"
	CategoryDenialOfService      = "denial_of_service"
	CategoryPrivilegeEscalation  = "privilege_escalation"
	CategoryRemoteCodeExecution  = "remote_code_execution"
	CategoryOther                = "other"
)

const (
	AppliesToCode           = "code"
	AppliesToConfig         = "config"
	AppliesToDependency     = "dependency"
	AppliesToInfrastructure = "infrastructure"
	AppliesToAll            = "all"
)

const (
	SourceNVD            = "nvd"
	SourceCISAKEV        = "cisa_kev"
	SourceCWE            = "cwe"
	SourceEPSS           = "epss"
	SourceExploitDB      = "exploitdb"
	SourceMITREAttack    = "mitre_attack"
	SourceCAPEC          = "capec"
	SourceNuclei         = "nuclei"
	SourceGitHubAdvisory = "github_advisory"
	SourceOSV            = "osv"
)
