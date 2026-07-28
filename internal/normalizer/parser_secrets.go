package normalizer

import "context"

type SecretsParser struct{}

func NewSecretsParser() *SecretsParser {
	return &SecretsParser{}
}

func (p *SecretsParser) Name() string {
	return "Secrets"
}

func (p *SecretsParser) Parse(ctx context.Context) ([]SecurityRule, error) {
	return buildSecretsRules(), nil
}

type secretRuleDefinition struct {
	id          string
	title       string
	description string
	severity    string
	pattern     string
	languages   []string
	cweIDs      []string
	tags        []string
}

func buildSecretsRules() []SecurityRule {
	definitions := getSecretsDefinitions()
	rules := make([]SecurityRule, 0, len(definitions))

	for _, definition := range definitions {
		rule := SecurityRule{
			ID:          definition.id,
			Source:      SourceSecrets,
			Category:    CategoryHardcodedSecrets,
			Severity:    definition.severity,
			Title:       definition.title,
			Description: definition.description,
			CheckInstruction: generateSecretsCheckInstruction(
				definition.title,
				definition.pattern,
				definition.description,
			),
			Remediation: "Move sensitive values to environment variables, a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.), or encrypted configuration files. Never commit secrets to version control.",
			Languages:   definition.languages,
			Frameworks:  []string{"all"},
			Platforms:   []string{"all"},
			AppliesTo:   AppliesToCode,
			CWEIDs:      definition.cweIDs,
			Tags:        definition.tags,
		}
		rules = append(rules, rule)
	}

	return rules
}

func generateSecretsCheckInstruction(title string, pattern string, description string) string {
	instruction := "Search the entire codebase (including configuration files, environment examples, and test files) for " + title + ". "
	instruction += "Look for patterns matching: " + pattern + ". "
	instruction += description + " "
	instruction += "Check .env.example, docker-compose files, CI configs, and source code. If found, flag as a critical security issue requiring immediate rotation of the exposed credential."
	return instruction
}

func getSecretsDefinitions() []secretRuleDefinition {
	return []secretRuleDefinition{
		{
			id:          "SEC-001",
			title:       "AWS Access Key ID Hardcoded",
			description: "AWS Access Key IDs starting with 'AKIA' followed by 16 alphanumeric characters should never appear in source code.",
			severity:    SeverityCritical,
			pattern:     "AKIA[0-9A-Z]{16}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "aws", "cloud", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-002",
			title:       "AWS Secret Access Key Hardcoded",
			description: "AWS Secret Access Keys are 40-character base64 strings often assigned to variables like 'aws_secret_access_key' or 'AWS_SECRET_KEY'.",
			severity:    SeverityCritical,
			pattern:     "aws_secret_access_key\\s*=\\s*[A-Za-z0-9/+=]{40}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "aws", "cloud", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-003",
			title:       "GitHub Personal Access Token Hardcoded",
			description: "GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_ prefixes followed by 36+ alphanumeric characters) must not be in source code.",
			severity:    SeverityCritical,
			pattern:     "gh[pousr]_[A-Za-z0-9_]{36,}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "github", "token", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-004",
			title:       "Slack Token Hardcoded",
			description: "Slack Bot/User/App tokens (xoxb-, xoxp-, xoxa-, xoxr-) should not be committed to source control.",
			severity:    SeverityHigh,
			pattern:     "xox[bpars]-[0-9a-zA-Z-]{10,}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "slack", "token", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-005",
			title:       "PEM Private Key Hardcoded",
			description: "PEM-encoded private keys (-----BEGIN RSA/EC/DSA/OPENSSH PRIVATE KEY-----) must never appear in source code or configuration files.",
			severity:    SeverityCritical,
			pattern:     "-----BEGIN\\s+(RSA|EC|DSA|OPENSSH|ENCRYPTED)?\\s*PRIVATE KEY-----",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-321", "CWE-798"},
			tags:        []string{"secrets", "private-key", "cryptographic", "credentials", "owasp-a02"},
		},
		{
			id:          "SEC-006",
			title:       "Generic API Key in Variable Assignment",
			description: "Variables named api_key, apikey, api_secret, secret_key, access_token, auth_token, or password assigned to string literals of 16+ characters.",
			severity:    SeverityHigh,
			pattern:     "(api_key|apikey|api_secret|secret_key|access_token|auth_token|password)\\s*[:=]\\s*['\"][A-Za-z0-9+/=_-]{16,}['\"]",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798", "CWE-259"},
			tags:        []string{"secrets", "generic", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-007",
			title:       "Google Cloud API Key Hardcoded",
			description: "Google Cloud API keys (AIza prefix followed by 35 characters) embedded in source code.",
			severity:    SeverityHigh,
			pattern:     "AIza[0-9A-Za-z_-]{35}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "google", "cloud", "gcp", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-008",
			title:       "Stripe Secret Key Hardcoded",
			description: "Stripe secret keys (sk_live_ or sk_test_ prefix) must not appear in source code. Use environment variables.",
			severity:    SeverityCritical,
			pattern:     "sk_(live|test)_[0-9a-zA-Z]{24,}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "stripe", "payment", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-009",
			title:       "Database Connection String with Password",
			description: "Database connection URIs containing embedded passwords (e.g., postgres://user:password@host, mongodb+srv://user:pass@cluster).",
			severity:    SeverityHigh,
			pattern:     "(postgres|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@[^/]+",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798", "CWE-259"},
			tags:        []string{"secrets", "database", "connection-string", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-010",
			title:       "JWT Secret Hardcoded",
			description: "JWT signing secrets assigned to variables like 'jwt_secret', 'JWT_SECRET', 'token_secret' with literal string values.",
			severity:    SeverityHigh,
			pattern:     "(jwt_secret|JWT_SECRET|token_secret|signing_key)\\s*[:=]\\s*['\"].{8,}['\"]",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798", "CWE-347"},
			tags:        []string{"secrets", "jwt", "authentication", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-011",
			title:       "SendGrid API Key Hardcoded",
			description: "SendGrid API keys (SG. prefix followed by base64 characters) should not be in source code.",
			severity:    SeverityHigh,
			pattern:     "SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "sendgrid", "email", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-012",
			title:       "Twilio Account Credentials Hardcoded",
			description: "Twilio Account SID (AC prefix + 32 hex chars) or Auth Token embedded in code.",
			severity:    SeverityHigh,
			pattern:     "AC[a-f0-9]{32}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "twilio", "sms", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-013",
			title:       "Heroku API Key Hardcoded",
			description: "Heroku API keys (UUID format in variable assignments) should use config vars instead.",
			severity:    SeverityHigh,
			pattern:     "HEROKU_API_KEY\\s*[:=]\\s*['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "heroku", "cloud", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-014",
			title:       "Mailgun API Key Hardcoded",
			description: "Mailgun API keys (key- prefix followed by 32 hex characters) found in source code.",
			severity:    SeverityHigh,
			pattern:     "key-[0-9a-f]{32}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "mailgun", "email", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-015",
			title:       "Azure Storage Account Key Hardcoded",
			description: "Azure Storage account keys (88-char base64 strings) in source code or config.",
			severity:    SeverityCritical,
			pattern:     "DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "azure", "cloud", "storage", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-016",
			title:       "OpenAI API Key Hardcoded",
			description: "OpenAI API keys (sk- prefix followed by 48+ characters) must not be committed to source code.",
			severity:    SeverityHigh,
			pattern:     "sk-[A-Za-z0-9]{48,}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "openai", "ai", "llm", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-017",
			title:       "NPM Access Token Hardcoded",
			description: "NPM tokens (npm_ prefix) or .npmrc auth tokens should not be in version control.",
			severity:    SeverityHigh,
			pattern:     "(npm_[A-Za-z0-9]{36}|//registry\\.npmjs\\.org/:_authToken=.+)",
			languages:   []string{"javascript", "typescript"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "npm", "registry", "supply-chain", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-018",
			title:       "Firebase Config with API Key Hardcoded",
			description: "Firebase configuration objects containing apiKey, authDomain, and project credentials in client-side code.",
			severity:    SeverityMedium,
			pattern:     "apiKey:\\s*['\"]AIza[0-9A-Za-z_-]{35}['\"]",
			languages:   []string{"javascript", "typescript"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "firebase", "google", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-019",
			title:       "Hardcoded Password in Source Code",
			description: "Literal password strings assigned to variables (password, passwd, pwd, pass) with non-empty values in source code.",
			severity:    SeverityHigh,
			pattern:     "(password|passwd|pwd)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798", "CWE-259"},
			tags:        []string{"secrets", "password", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-020",
			title:       "Supabase Service Role Key Hardcoded",
			description: "Supabase service_role keys (JWT format starting with eyJ) should never be exposed in client-side code.",
			severity:    SeverityCritical,
			pattern:     "service_role.*eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "supabase", "database", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-021",
			title:       "Discord Bot Token Hardcoded",
			description: "Discord bot tokens (base64-encoded, typically 59+ characters following a pattern with dots) in source code.",
			severity:    SeverityHigh,
			pattern:     "[MN][A-Za-z0-9]{23,}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27,}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "discord", "bot", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-022",
			title:       "GitLab Personal Access Token Hardcoded",
			description: "GitLab tokens (glpat- prefix followed by 20+ characters) should not be committed.",
			severity:    SeverityCritical,
			pattern:     "glpat-[A-Za-z0-9_-]{20,}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "gitlab", "token", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-023",
			title:       "Shopify Access Token Hardcoded",
			description: "Shopify access tokens (shpat_, shpca_, shppa_ prefixes) found in source code.",
			severity:    SeverityHigh,
			pattern:     "shp(at|ca|pa)_[a-fA-F0-9]{32,}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "shopify", "ecommerce", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-024",
			title:       "PyPI Upload Token Hardcoded",
			description: "PyPI API tokens (pypi- prefix) for package uploads must use environment variables.",
			severity:    SeverityHigh,
			pattern:     "pypi-[A-Za-z0-9_-]{100,}",
			languages:   []string{"python"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "pypi", "registry", "supply-chain", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-025",
			title:       "Datadog API Key Hardcoded",
			description: "Datadog API keys (32 hex characters) or App keys (40 hex characters) in source code.",
			severity:    SeverityHigh,
			pattern:     "(DD_API_KEY|datadog_api_key)\\s*[:=]\\s*['\"][a-f0-9]{32}['\"]",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "datadog", "monitoring", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-026",
			title:       "Cloudflare API Token Hardcoded",
			description: "Cloudflare API tokens or Global API Keys in source code or configuration.",
			severity:    SeverityHigh,
			pattern:     "(CF_API_TOKEN|CLOUDFLARE_API_KEY)\\s*[:=]\\s*['\"][A-Za-z0-9_-]{37,}['\"]",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "cloudflare", "cdn", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-027",
			title:       "DigitalOcean Access Token Hardcoded",
			description: "DigitalOcean personal access tokens (dop_v1_ prefix) should not be in code.",
			severity:    SeverityHigh,
			pattern:     "dop_v1_[a-f0-9]{64}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "digitalocean", "cloud", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-028",
			title:       "Vercel Token Hardcoded",
			description: "Vercel deployment tokens in source code or CI configuration.",
			severity:    SeverityHigh,
			pattern:     "(VERCEL_TOKEN|vercel_token)\\s*[:=]\\s*['\"][A-Za-z0-9]{24,}['\"]",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "vercel", "deployment", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-029",
			title:       "Anthropic API Key Hardcoded",
			description: "Anthropic API keys (sk-ant- prefix) for Claude models must not be in source code.",
			severity:    SeverityHigh,
			pattern:     "sk-ant-[A-Za-z0-9_-]{80,}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "anthropic", "ai", "llm", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-030",
			title:       "Google OAuth Client Secret Hardcoded",
			description: "Google OAuth client secrets (GOCSPX- prefix) embedded in client-side or server code.",
			severity:    SeverityHigh,
			pattern:     "GOCSPX-[A-Za-z0-9_-]{28}",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"secrets", "google", "oauth", "credentials", "owasp-a07"},
		},
		{
			id:          "SEC-031",
			title:       "Terraform State with Secrets Committed",
			description: "Terraform state files (*.tfstate) containing sensitive outputs or resource credentials committed to version control.",
			severity:    SeverityCritical,
			pattern:     "\\.tfstate files in repository, or terraform.tfstate content with sensitive attributes",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-200", "CWE-798"},
			tags:        []string{"secrets", "terraform", "iac", "state-file", "owasp-a07"},
		},
		{
			id:          "SEC-032",
			title:       "PGP Private Key Block Hardcoded",
			description: "PGP private key blocks (-----BEGIN PGP PRIVATE KEY BLOCK-----) in source code.",
			severity:    SeverityCritical,
			pattern:     "-----BEGIN PGP PRIVATE KEY BLOCK-----",
			languages:   []string{"all"},
			cweIDs:      []string{"CWE-321", "CWE-798"},
			tags:        []string{"secrets", "pgp", "private-key", "cryptographic", "owasp-a02"},
		},
	}
}
