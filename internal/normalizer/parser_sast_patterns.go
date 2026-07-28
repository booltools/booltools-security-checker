package normalizer

import "context"

type SASTPatternParser struct{}

func NewSASTPatternParser() *SASTPatternParser {
	return &SASTPatternParser{}
}

func (p *SASTPatternParser) Name() string {
	return "SAST Patterns"
}

func (p *SASTPatternParser) Parse(ctx context.Context) ([]SecurityRule, error) {
	var rules []SecurityRule
	rules = append(rules, buildJavaScriptSASTRules()...)
	rules = append(rules, buildPythonSASTRules()...)
	rules = append(rules, buildGoSASTRules()...)
	rules = append(rules, buildJavaSASTRules()...)
	rules = append(rules, buildCrosslanguageSASTRules()...)
	return rules, nil
}

type sastRuleDefinition struct {
	id               string
	title            string
	description      string
	severity         string
	category         string
	languages        []string
	frameworks       []string
	cweIDs           []string
	tags             []string
	checkInstruction string
	remediation      string
}

func buildSASTRulesFromDefinitions(definitions []sastRuleDefinition) []SecurityRule {
	rules := make([]SecurityRule, 0, len(definitions))
	for _, definition := range definitions {
		rule := SecurityRule{
			ID:               definition.id,
			Source:           SourceSASTPatterns,
			Category:         definition.category,
			Severity:         definition.severity,
			Title:            definition.title,
			Description:      definition.description,
			CheckInstruction: definition.checkInstruction,
			Remediation:      definition.remediation,
			Languages:        definition.languages,
			Frameworks:       definition.frameworks,
			Platforms:        []string{"all"},
			AppliesTo:        AppliesToCode,
			CWEIDs:           definition.cweIDs,
			Tags:             definition.tags,
		}
		rules = append(rules, rule)
	}
	return rules
}

func buildJavaScriptSASTRules() []SecurityRule {
	return buildSASTRulesFromDefinitions([]sastRuleDefinition{
		{
			id:          "SAST-JS-001",
			title:       "Prototype Pollution",
			description: "Prototype pollution occurs when user input is used to modify Object.prototype, allowing attackers to inject properties into all JavaScript objects. This can lead to denial of service, property injection, or remote code execution.",
			severity:    SeverityHigh,
			category:    CategoryInjection,
			languages:   []string{"javascript", "typescript"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-1321"},
			tags:        []string{"sast", "prototype-pollution", "javascript", "injection"},
			checkInstruction: "Search for patterns that allow user-controlled input to modify object prototypes. Look for: " +
				"1) Recursive merge/extend functions that don't check for '__proto__', 'constructor', or 'prototype' keys. " +
				"2) Object.assign() or spread operators with unsanitized user input as source. " +
				"3) Lodash _.merge, _.set, _.defaultsDeep with user-controlled paths. " +
				"4) Direct property assignment using bracket notation with user-controlled keys (obj[userInput] = value). " +
				"Flag if any path allows setting __proto__.polluted, constructor.prototype, or Object.prototype properties.",
			remediation: "Use Object.create(null) for lookup objects, validate/allowlist property names, use Map instead of plain objects for user data, or freeze Object.prototype in critical paths.",
		},
		{
			id:          "SAST-JS-002",
			title:       "NoSQL Injection",
			description: "NoSQL injection occurs when user input is passed directly into MongoDB/Mongoose queries without sanitization, allowing attackers to manipulate query logic using operators like $gt, $ne, $regex.",
			severity:    SeverityHigh,
			category:    CategoryInjection,
			languages:   []string{"javascript", "typescript"},
			frameworks:  []string{"mongodb", "mongoose", "all"},
			cweIDs:      []string{"CWE-943"},
			tags:        []string{"sast", "nosql-injection", "mongodb", "injection", "owasp-a03"},
			checkInstruction: "Search for MongoDB/Mongoose query operations (find, findOne, updateOne, deleteMany, aggregate) where user input (req.body, req.query, req.params) is passed directly into query objects without sanitization. " +
				"Look for: 1) db.collection.find({ field: req.body.value }) — an attacker can send { '$gt': '' } to bypass filters. " +
				"2) Model.find(req.query) — passing entire query object from request. " +
				"3) Missing mongo-sanitize or express-mongo-sanitize middleware. " +
				"4) String concatenation in aggregation pipelines. " +
				"Flag if user input flows into query operators without explicit type checking or sanitization.",
			remediation: "Use express-mongo-sanitize middleware, validate/cast input types explicitly before queries, use parameterized queries, or sanitize input to strip $ operators.",
		},
		{
			id:          "SAST-JS-003",
			title:       "Regular Expression Denial of Service (ReDoS)",
			description: "Regex patterns with nested quantifiers or overlapping alternations can cause catastrophic backtracking when processing crafted input, freezing the event loop.",
			severity:    SeverityMedium,
			category:    CategoryDenialOfService,
			languages:   []string{"javascript", "typescript"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-1333", "CWE-400"},
			tags:        []string{"sast", "redos", "regex", "denial-of-service"},
			checkInstruction: "Search for regular expressions with potentially catastrophic backtracking patterns: " +
				"1) Nested quantifiers: (a+)+ , (a*)*b , (a|b)* followed by similar patterns. " +
				"2) Overlapping alternations: (a|a)+ , (.*a){10}. " +
				"3) User-controlled regex: new RegExp(userInput) without sanitization. " +
				"4) Complex patterns applied to user-provided strings without length limits. " +
				"Use tools like 'safe-regex' or 'redos-detector' patterns. Flag any regex used on user input that has nested quantifiers or unbounded repetitions.",
			remediation: "Use safe-regex or re2 library for user input validation, add input length limits before regex, avoid nested quantifiers, or use non-backtracking engines.",
		},
		{
			id:          "SAST-JS-004",
			title:       "Insufficient postMessage Origin Validation",
			description: "Event listeners for 'message' events that don't validate event.origin allow any website to send messages to the application, potentially triggering unauthorized actions.",
			severity:    SeverityMedium,
			category:    CategoryBrokenAccessControl,
			languages:   []string{"javascript", "typescript"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-346", "CWE-20"},
			tags:        []string{"sast", "postmessage", "origin-validation", "browser", "owasp-a01"},
			checkInstruction: "Search for window.addEventListener('message', ...) handlers that: " +
				"1) Don't check event.origin at all before processing the message data. " +
				"2) Use wildcard origin check (event.origin !== '*'). " +
				"3) Use partial/insufficient origin checks (event.origin.includes('trusted.com') — vulnerable to 'attacker-trusted.com'). " +
				"Also check postMessage calls that use '*' as targetOrigin: window.postMessage(data, '*'). " +
				"Flag any message handler without strict event.origin === 'https://expected-domain.com' validation.",
			remediation: "Always validate event.origin against an exact allowlist of trusted origins. Use strict equality comparison with the full origin URL including protocol.",
		},
		{
			id:          "SAST-JS-005",
			title:       "Use of dangerouslySetInnerHTML Without Sanitization",
			description: "React's dangerouslySetInnerHTML renders raw HTML, bypassing React's XSS protections. If the HTML contains user input, it enables stored/reflected XSS attacks.",
			severity:    SeverityHigh,
			category:    CategoryInjection,
			languages:   []string{"javascript", "typescript"},
			frameworks:  []string{"react", "next", "all"},
			cweIDs:      []string{"CWE-79"},
			tags:        []string{"sast", "xss", "react", "dangerously-set-inner-html", "owasp-a03", "sans-top-25"},
			checkInstruction: "Search for all uses of dangerouslySetInnerHTML in React components. For each occurrence: " +
				"1) Trace the __html value — does it contain or derive from user input (props, state from API, URL params, form data)? " +
				"2) Is the HTML sanitized with DOMPurify.sanitize() or similar before being set? " +
				"3) Check for innerHTML assignments outside React as well. " +
				"Flag if user-derived content is passed to dangerouslySetInnerHTML without sanitization through DOMPurify or equivalent.",
			remediation: "Use DOMPurify.sanitize() on all HTML before setting via dangerouslySetInnerHTML. Prefer rendering content with React components instead of raw HTML. Use Content-Security-Policy headers as defense-in-depth.",
		},
		{
			id:          "SAST-JS-006",
			title:       "JWT 'none' Algorithm Accepted",
			description: "JWT verification that accepts the 'none' algorithm allows attackers to forge tokens by removing the signature. This completely bypasses authentication.",
			severity:    SeverityCritical,
			category:    CategoryAuthFailure,
			languages:   []string{"javascript", "typescript"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-347"},
			tags:        []string{"sast", "jwt", "none-algorithm", "authentication", "owasp-a02"},
			checkInstruction: "Search for JWT verification code and check: " +
				"1) jwt.verify() calls without algorithms option (defaults may allow 'none'). " +
				"2) algorithms array that includes 'none': { algorithms: ['none', 'HS256'] }. " +
				"3) Custom JWT parsing that doesn't validate the alg header. " +
				"4) Using jwt.decode() (which doesn't verify) instead of jwt.verify() for authentication decisions. " +
				"5) Libraries: jsonwebtoken, jose, jwt-simple — check each for algorithm enforcement. " +
				"Flag if the JWT verification doesn't explicitly restrict algorithms to a secure set.",
			remediation: "Always specify algorithms explicitly in jwt.verify(): { algorithms: ['RS256'] }. Never include 'none'. Use asymmetric algorithms (RS256, ES256) over symmetric (HS256) when possible.",
		},
		{
			id:          "SAST-JS-007",
			title:       "Insecure Cookie Configuration",
			description: "Cookies storing session tokens or sensitive data without HttpOnly, Secure, and SameSite attributes are vulnerable to theft via XSS, man-in-the-middle, and CSRF attacks.",
			severity:    SeverityMedium,
			category:    CategoryInsecureCookie,
			languages:   []string{"javascript", "typescript"},
			frameworks:  []string{"express", "koa", "fastify", "next", "all"},
			cweIDs:      []string{"CWE-614", "CWE-1004"},
			tags:        []string{"sast", "cookie", "httponly", "secure", "samesite", "owasp-a05"},
			checkInstruction: "Search for cookie-setting operations (res.cookie(), Set-Cookie headers, cookie libraries) and verify: " +
				"1) HttpOnly flag is set for session/auth cookies (prevents JavaScript access). " +
				"2) Secure flag is set (cookie only sent over HTTPS). " +
				"3) SameSite is set to 'Strict' or 'Lax' (prevents CSRF). " +
				"4) Check cookie-session, express-session, next-auth configurations. " +
				"Flag any authentication or session cookie missing HttpOnly, Secure, or SameSite attributes.",
			remediation: "Set all session/auth cookies with: { httpOnly: true, secure: true, sameSite: 'strict' }. Configure session middleware with these defaults.",
		},
		{
			id:          "SAST-JS-008",
			title:       "Electron Disabled Web Security",
			description: "Electron apps with webSecurity: false, nodeIntegration: true, or contextIsolation: false expose the renderer process to web attacks that can escalate to full OS access.",
			severity:    SeverityHigh,
			category:    CategoryMisconfiguration,
			languages:   []string{"javascript", "typescript"},
			frameworks:  []string{"electron", "all"},
			cweIDs:      []string{"CWE-16"},
			tags:        []string{"sast", "electron", "web-security", "desktop", "owasp-a05"},
			checkInstruction: "Search for Electron BrowserWindow creation and webPreferences configuration: " +
				"1) webSecurity: false — disables same-origin policy. " +
				"2) nodeIntegration: true — gives renderer full Node.js access. " +
				"3) contextIsolation: false — allows preload scripts to leak Node.js to page. " +
				"4) allowRunningInsecureContent: true — loads HTTP in HTTPS context. " +
				"5) Remote module enabled. " +
				"Flag any insecure webPreferences configuration.",
			remediation: "Use contextIsolation: true, nodeIntegration: false, sandbox: true. Communicate with main process only through preload scripts and ipcRenderer.",
		},
		{
			id:          "SAST-JS-009",
			title:       "Open Redirect via Unvalidated URL",
			description: "Redirecting users to URLs derived from user input without validation enables phishing attacks where victims are sent to attacker-controlled sites from a trusted domain.",
			severity:    SeverityMedium,
			category:    CategoryInjection,
			languages:   []string{"javascript", "typescript"},
			frameworks:  []string{"express", "next", "koa", "all"},
			cweIDs:      []string{"CWE-601"},
			tags:        []string{"sast", "open-redirect", "phishing", "owasp-a01"},
			checkInstruction: "Search for redirect operations where the destination URL comes from user input: " +
				"1) res.redirect(req.query.url) or res.redirect(req.body.redirect). " +
				"2) window.location = userInput or window.location.href = params.get('next'). " +
				"3) Next.js router.push(userControlledPath). " +
				"4) HTTP 301/302 responses with Location header from user input. " +
				"Flag if the redirect URL is not validated against an allowlist of trusted domains/paths.",
			remediation: "Validate redirect URLs against an allowlist of trusted domains. Use relative paths only, or parse the URL and verify the hostname. Reject URLs starting with '//' or containing '@'.",
		},
		{
			id:          "SAST-JS-010",
			title:       "GraphQL Introspection Enabled in Production",
			description: "GraphQL introspection queries expose the entire API schema, revealing all types, queries, mutations, and their arguments. This provides attackers a complete API map.",
			severity:    SeverityMedium,
			category:    CategoryExposure,
			languages:   []string{"javascript", "typescript"},
			frameworks:  []string{"graphql", "apollo", "all"},
			cweIDs:      []string{"CWE-200"},
			tags:        []string{"sast", "graphql", "introspection", "information-exposure", "owasp-a01"},
			checkInstruction: "Search for GraphQL server configurations and verify: " +
				"1) Apollo Server: introspection is not set to true in production (introspection: process.env.NODE_ENV !== 'production'). " +
				"2) graphql-yoga, express-graphql: similar introspection settings. " +
				"3) No depth limiting on queries (enables nested query DoS). " +
				"4) No query complexity analysis. " +
				"Flag if introspection is enabled without environment-based restriction.",
			remediation: "Disable introspection in production: { introspection: process.env.NODE_ENV !== 'production' }. Add query depth limiting and complexity analysis.",
		},
		{
			id:          "SAST-JS-011",
			title:       "Allocation of Resources Without Limits (DoS)",
			description: "APIs that accept unbounded input (file uploads, JSON payloads, arrays, query results) without size limits can be exploited to exhaust server memory or CPU.",
			severity:    SeverityMedium,
			category:    CategoryDenialOfService,
			languages:   []string{"javascript", "typescript"},
			frameworks:  []string{"express", "fastify", "koa", "all"},
			cweIDs:      []string{"CWE-770"},
			tags:        []string{"sast", "dos", "resource-exhaustion", "rate-limiting"},
			checkInstruction: "Check for resource allocation without limits: " +
				"1) Express body-parser without limit option: express.json() should have { limit: '1mb' }. " +
				"2) File upload without maxFileSize (multer, formidable, busboy). " +
				"3) No request rate limiting middleware (express-rate-limit). " +
				"4) Database queries without LIMIT clause that return user-facing data. " +
				"5) Array/collection processing without length validation on user-provided arrays. " +
				"Flag any endpoint accepting unbounded input without size/rate limits.",
			remediation: "Set body parser limits, add file size limits, implement rate limiting middleware, paginate all list endpoints, and validate array lengths in input.",
		},
		{
			id:          "SAST-JS-012",
			title:       "Permissive CORS Configuration",
			description: "CORS configured with origin: '*' or dynamically reflecting the Origin header without validation allows any website to make authenticated cross-origin requests.",
			severity:    SeverityMedium,
			category:    CategoryBrokenAccessControl,
			languages:   []string{"javascript", "typescript"},
			frameworks:  []string{"express", "fastify", "koa", "all"},
			cweIDs:      []string{"CWE-942", "CWE-346"},
			tags:        []string{"sast", "cors", "cross-origin", "access-control", "owasp-a05", "owasp-a07"},
			checkInstruction: "Search for CORS configuration and Access-Control-Allow-Origin headers: " +
				"1) cors({ origin: '*' }) with credentials: true — browsers block this but the intent reveals misunderstanding. " +
				"2) Reflecting req.headers.origin directly without allowlist: cors({ origin: req.headers.origin }). " +
				"3) Regex-based origin validation with insufficient patterns (e.g., /trusted\\.com/ matches 'attacker-trusted.com'). " +
				"4) Access-Control-Allow-Credentials: true with a permissive origin. " +
				"Flag any CORS configuration that doesn't use a strict allowlist of trusted origins.",
			remediation: "Use a strict origin allowlist: cors({ origin: ['https://app.example.com'], credentials: true }). Never reflect the Origin header without validation.",
		},
	})
}

func buildPythonSASTRules() []SecurityRule {
	return buildSASTRulesFromDefinitions([]sastRuleDefinition{
		{
			id:          "SAST-PY-001",
			title:       "Unsafe Deserialization with pickle",
			description: "Python's pickle module can execute arbitrary code during deserialization. Loading pickled data from untrusted sources enables remote code execution.",
			severity:    SeverityCritical,
			category:    CategoryRemoteCodeExecution,
			languages:   []string{"python"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-502"},
			tags:        []string{"sast", "pickle", "deserialization", "rce", "python", "owasp-a08", "sans-top-25"},
			checkInstruction: "Search for pickle usage with untrusted data: " +
				"1) pickle.loads() or pickle.load() on data from network, files, or user input. " +
				"2) shelve module (uses pickle internally). " +
				"3) joblib.load() with untrusted files. " +
				"4) PyYAML yaml.load() without Loader=SafeLoader (yaml.safe_load preferred). " +
				"5) marshal.loads() with external data. " +
				"Flag any deserialization of untrusted data using these modules.",
			remediation: "Use json, msgpack, or Protocol Buffers for untrusted data. If pickle is required, use hmac signing to verify data integrity before loading. Use yaml.safe_load() instead of yaml.load().",
		},
		{
			id:          "SAST-PY-002",
			title:       "Flask Debug Mode in Production",
			description: "Flask's debug mode (app.run(debug=True)) enables the Werkzeug debugger which provides an interactive Python console accessible via the browser, enabling RCE.",
			severity:    SeverityCritical,
			category:    CategoryMisconfiguration,
			languages:   []string{"python"},
			frameworks:  []string{"flask", "all"},
			cweIDs:      []string{"CWE-489", "CWE-215"},
			tags:        []string{"sast", "flask", "debug", "rce", "python", "owasp-a05"},
			checkInstruction: "Search for Flask application configuration: " +
				"1) app.run(debug=True) without environment check. " +
				"2) DEBUG = True in config without restriction to development. " +
				"3) FLASK_DEBUG=1 in production environment files. " +
				"4) Django DEBUG = True in settings.py without environment-based switching. " +
				"Flag if debug mode can be active in production deployment.",
			remediation: "Never hardcode debug=True. Use environment variables: app.run(debug=os.environ.get('FLASK_ENV') == 'development'). For Django: DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'.",
		},
		{
			id:          "SAST-PY-003",
			title:       "SQL Injection via String Formatting",
			description: "Building SQL queries with f-strings, .format(), or % formatting with user input allows attackers to inject malicious SQL commands.",
			severity:    SeverityHigh,
			category:    CategoryInjection,
			languages:   []string{"python"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-89"},
			tags:        []string{"sast", "sql-injection", "string-formatting", "python", "owasp-a03", "sans-top-25"},
			checkInstruction: "Search for SQL queries built with string interpolation: " +
				"1) f\"SELECT * FROM users WHERE name = '{user_input}'\" " +
				"2) \"SELECT * FROM users WHERE id = %s\" % user_id (without parameterized query) " +
				"3) cursor.execute(f\"...\") or cursor.execute(query.format(...)). " +
				"4) SQLAlchemy text() with string formatting instead of bound parameters. " +
				"5) Django raw() queries with string concatenation. " +
				"Flag if user input is interpolated into SQL strings rather than passed as parameters.",
			remediation: "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)). Use ORM query builders. For SQLAlchemy: text('SELECT * FROM users WHERE id = :id').bindparams(id=user_id).",
		},
		{
			id:          "SAST-PY-004",
			title:       "Use of eval/exec with User Input",
			description: "Python's eval() and exec() execute arbitrary Python code. If user input reaches these functions, attackers gain full code execution on the server.",
			severity:    SeverityCritical,
			category:    CategoryRemoteCodeExecution,
			languages:   []string{"python"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-94", "CWE-95"},
			tags:        []string{"sast", "code-injection", "eval", "exec", "python", "owasp-a03", "sans-top-25"},
			checkInstruction: "Search for dangerous code execution functions: " +
				"1) eval(user_input) or exec(user_input). " +
				"2) compile() + exec() with user-controlled code. " +
				"3) __import__(user_input) for dynamic imports. " +
				"4) getattr(module, user_input)() for dynamic method calls. " +
				"5) Template engines without sandboxing (Jinja2 without sandbox, Mako). " +
				"Flag any path where user-controlled data reaches code execution functions.",
			remediation: "Use ast.literal_eval() for safe evaluation of literals. Replace eval with specific parsers (json.loads, int(), float()). Use allowlists for dynamic dispatch instead of getattr with user input.",
		},
		{
			id:          "SAST-PY-005",
			title:       "Weak Cryptographic Algorithm Usage",
			description: "Use of MD5, SHA1 for password hashing or security-sensitive operations, or DES/RC4/ECB mode for encryption, provides inadequate security against modern attacks.",
			severity:    SeverityMedium,
			category:    CategoryInsecureCrypto,
			languages:   []string{"python"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-327", "CWE-328"},
			tags:        []string{"sast", "cryptography", "weak-algorithm", "python", "owasp-a02"},
			checkInstruction: "Search for weak cryptographic usage: " +
				"1) hashlib.md5() or hashlib.sha1() used for password storage or security tokens. " +
				"2) DES, 3DES, RC4, Blowfish cipher usage from cryptography or PyCryptodome. " +
				"3) AES in ECB mode (insecure for most uses). " +
				"4) RSA with key size < 2048 bits. " +
				"5) Using random.random() instead of secrets module for security purposes. " +
				"Flag weak algorithms used in security-sensitive contexts (not checksums/caching).",
			remediation: "Use bcrypt/argon2/scrypt for passwords. Use AES-256-GCM for encryption. Use SHA-256+ for integrity. Use secrets module for tokens. Use RSA >= 2048 bits or ECDSA.",
		},
		{
			id:          "SAST-PY-006",
			title:       "Server-Side Template Injection (SSTI)",
			description: "Rendering user input as a template string allows attackers to execute arbitrary code through template syntax ({{ config }}, {% import os %}).",
			severity:    SeverityCritical,
			category:    CategoryRemoteCodeExecution,
			languages:   []string{"python"},
			frameworks:  []string{"flask", "django", "jinja2", "all"},
			cweIDs:      []string{"CWE-1336", "CWE-94"},
			tags:        []string{"sast", "ssti", "template-injection", "rce", "python", "owasp-a03"},
			checkInstruction: "Search for template rendering with user-controlled template strings: " +
				"1) render_template_string(user_input) in Flask. " +
				"2) Template(user_input).render() in Jinja2/Django. " +
				"3) Jinja2 Environment with undefined=Undefined (allows attribute access). " +
				"4) format_map() or Formatter with user-controlled format strings. " +
				"Flag if user input is used AS the template rather than as template DATA.",
			remediation: "Never use user input as template source. Always pass user data as template context variables: render_template('page.html', data=user_input). Use sandboxed Jinja2 environment if dynamic templates are unavoidable.",
		},
		{
			id:          "SAST-PY-007",
			title:       "Binding to All Network Interfaces",
			description: "Binding server to 0.0.0.0 in production makes the service accessible from all network interfaces including public ones. This may unintentionally expose internal services.",
			severity:    SeverityMedium,
			category:    CategoryMisconfiguration,
			languages:   []string{"python"},
			frameworks:  []string{"flask", "django", "fastapi", "all"},
			cweIDs:      []string{"CWE-284"},
			tags:        []string{"sast", "network", "binding", "exposure", "python", "owasp-a01"},
			checkInstruction: "Search for server binding configuration: " +
				"1) app.run(host='0.0.0.0') in Flask without reverse proxy. " +
				"2) uvicorn with --host 0.0.0.0 in production. " +
				"3) socket.bind(('0.0.0.0', port)) for internal services. " +
				"4) Django ALLOWED_HOSTS = ['*']. " +
				"Flag if production services bind to 0.0.0.0 without network-level access controls.",
			remediation: "Bind to 127.0.0.1 for services behind a reverse proxy. Use proper network segmentation. For Django, set ALLOWED_HOSTS to specific domains.",
		},
	})
}

func buildGoSASTRules() []SecurityRule {
	return buildSASTRulesFromDefinitions([]sastRuleDefinition{
		{
			id:          "SAST-GO-001",
			title:       "SQL Injection via String Concatenation in Go",
			description: "Building SQL queries with fmt.Sprintf or string concatenation with user input in Go database operations allows SQL injection attacks.",
			severity:    SeverityHigh,
			category:    CategoryInjection,
			languages:   []string{"go"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-89"},
			tags:        []string{"sast", "sql-injection", "go", "database", "owasp-a03", "sans-top-25"},
			checkInstruction: "Search for SQL queries built with string operations in Go: " +
				"1) db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE id = '%s'\", userInput)). " +
				"2) db.Exec(\"DELETE FROM items WHERE id = \" + id). " +
				"3) sqlx.Get() or sqlx.Select() with formatted query strings. " +
				"4) GORM Raw() with string concatenation. " +
				"Flag if user input is interpolated into SQL strings instead of using ? placeholders or named parameters.",
			remediation: "Use parameterized queries: db.Query('SELECT * FROM users WHERE id = ?', userInput). For GORM: db.Where('id = ?', id). For sqlx: sqlx.Get(&user, 'SELECT * FROM users WHERE id = $1', id).",
		},
		{
			id:          "SAST-GO-002",
			title:       "Unsafe HTML Template Rendering in Go",
			description: "Using text/template instead of html/template for web responses, or using template.HTML() to mark user input as safe, disables HTML escaping and enables XSS.",
			severity:    SeverityHigh,
			category:    CategoryInjection,
			languages:   []string{"go"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-79"},
			tags:        []string{"sast", "xss", "template", "go", "owasp-a03", "sans-top-25"},
			checkInstruction: "Search for template rendering vulnerabilities in Go: " +
				"1) import \"text/template\" used for HTML responses instead of \"html/template\". " +
				"2) template.HTML(userInput) casting user data as safe HTML. " +
				"3) template.JS(userInput) or template.CSS(userInput) with user data. " +
				"4) Direct string writing to http.ResponseWriter with user data and Content-Type: text/html. " +
				"Flag if user-controlled data bypasses html/template auto-escaping.",
			remediation: "Always use html/template for web output. Never cast user input with template.HTML(). If raw HTML is needed, sanitize with bluemonday before marking as safe.",
		},
		{
			id:          "SAST-GO-003",
			title:       "Insecure TLS Configuration in Go",
			description: "Go TLS configurations with InsecureSkipVerify: true, MinVersion below TLS 1.2, or weak cipher suites disable critical security checks.",
			severity:    SeverityHigh,
			category:    CategoryInsecureCrypto,
			languages:   []string{"go"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-295", "CWE-327"},
			tags:        []string{"sast", "tls", "certificate", "go", "owasp-a02"},
			checkInstruction: "Search for TLS configuration in Go: " +
				"1) &tls.Config{InsecureSkipVerify: true} — disables certificate validation. " +
				"2) MinVersion: tls.VersionTLS10 or tls.VersionTLS11 (below 1.2). " +
				"3) Missing MinVersion field (defaults to TLS 1.0 in older Go versions). " +
				"4) Custom cipher suites including RC4, 3DES, or NULL ciphers. " +
				"5) http.Transport with TLSClientConfig disabling verification. " +
				"Flag any TLS configuration that weakens connection security.",
			remediation: "Set InsecureSkipVerify: false (default). Set MinVersion: tls.VersionTLS12. Let Go select cipher suites automatically (its defaults are secure). Only skip verification in development with explicit checks.",
		},
		{
			id:          "SAST-GO-004",
			title:       "Race Condition in Go Concurrent Access",
			description: "Shared mutable state accessed from multiple goroutines without synchronization leads to data races, which can cause authentication bypasses, double-spending, or data corruption.",
			severity:    SeverityMedium,
			category:    CategoryInsecureDesign,
			languages:   []string{"go"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-362", "CWE-367"},
			tags:        []string{"sast", "race-condition", "concurrency", "go"},
			checkInstruction: "Search for potential data races in Go: " +
				"1) Package-level variables modified by HTTP handlers (maps, slices, counters) without sync.Mutex. " +
				"2) Map read/write from multiple goroutines without sync.RWMutex or sync.Map. " +
				"3) Check-then-act patterns without locking (if !exists { create() }). " +
				"4) Struct fields accessed concurrently without atomic operations or mutexes. " +
				"Flag shared state modified by concurrent handlers without proper synchronization.",
			remediation: "Use sync.Mutex/RWMutex for shared state, sync.Map for concurrent map access, sync/atomic for counters, or redesign to use channels. Run go test -race regularly.",
		},
		{
			id:          "SAST-GO-005",
			title:       "Path Traversal in File Operations",
			description: "File operations using user-provided paths without sanitization allow attackers to read/write arbitrary files outside the intended directory (e.g., ../../etc/passwd).",
			severity:    SeverityHigh,
			category:    CategoryInjection,
			languages:   []string{"go"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-22"},
			tags:        []string{"sast", "path-traversal", "file", "go", "owasp-a01", "sans-top-25"},
			checkInstruction: "Search for file operations with user-controlled paths: " +
				"1) os.Open(userInput) or os.ReadFile(filepath.Join(baseDir, userInput)) without Clean. " +
				"2) http.ServeFile(w, r, userPath) without path validation. " +
				"3) filepath.Join() that doesn't verify the result stays within the base directory. " +
				"4) Missing filepath.Clean() and prefix check after joining. " +
				"Flag if user input is used in file paths without verifying the resolved path is within the allowed directory.",
			remediation: "Use filepath.Clean() then verify strings.HasPrefix(cleanedPath, allowedBase). Or use fs.FS interface which inherently restricts to a subtree. Never use user input directly in file paths.",
		},
	})
}

func buildJavaSASTRules() []SecurityRule {
	return buildSASTRulesFromDefinitions([]sastRuleDefinition{
		{
			id:          "SAST-JAVA-001",
			title:       "XML External Entity (XXE) Injection in Java",
			description: "Java XML parsers (DocumentBuilderFactory, SAXParser, XMLInputFactory) with default configuration process external entities, allowing file disclosure and SSRF.",
			severity:    SeverityHigh,
			category:    CategoryInjection,
			languages:   []string{"java", "kotlin"},
			frameworks:  []string{"spring", "all"},
			cweIDs:      []string{"CWE-611"},
			tags:        []string{"sast", "xxe", "xml", "java", "owasp-a05"},
			checkInstruction: "Search for XML parser usage without secure configuration: " +
				"1) DocumentBuilderFactory without setFeature('http://apache.org/xml/features/disallow-doctype-decl', true). " +
				"2) SAXParserFactory without disabling external entities. " +
				"3) XMLInputFactory without XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES set to false. " +
				"4) Spring @RequestBody with XML content type without secure parser configuration. " +
				"Flag XML parsers that haven't explicitly disabled external entity processing.",
			remediation: "Disable DTDs and external entities: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true). For Spring, configure Jackson XML mapper with secure defaults.",
		},
		{
			id:          "SAST-JAVA-002",
			title:       "Insecure Deserialization in Java",
			description: "Java ObjectInputStream deserializes arbitrary objects from byte streams. Untrusted deserialization enables remote code execution through gadget chains.",
			severity:    SeverityCritical,
			category:    CategoryRemoteCodeExecution,
			languages:   []string{"java", "kotlin"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-502"},
			tags:        []string{"sast", "deserialization", "rce", "java", "owasp-a08", "sans-top-25"},
			checkInstruction: "Search for Java deserialization of untrusted data: " +
				"1) new ObjectInputStream(inputStream).readObject() from network/file/user sources. " +
				"2) XMLDecoder with external input. " +
				"3) XStream.fromXML() without type allowlisting. " +
				"4) Jackson with enableDefaultTyping() or @JsonTypeInfo on untrusted inputs. " +
				"5) Apache Commons Collections in classpath (gadget chain source). " +
				"Flag ObjectInputStream.readObject() usage with untrusted data sources.",
			remediation: "Avoid Java serialization for untrusted data. Use JSON/Protobuf. If required, implement ObjectInputFilter (Java 9+) with strict allowlists. Remove gadget chain libraries or use notsoserial/SerialKiller.",
		},
		{
			id:          "SAST-JAVA-003",
			title:       "Spring Mass Assignment / Autobinding",
			description: "Spring MVC automatically binds request parameters to object fields. Without @InitBinder restrictions, attackers can set unintended fields (role, isAdmin, price).",
			severity:    SeverityHigh,
			category:    CategoryBrokenAccessControl,
			languages:   []string{"java", "kotlin"},
			frameworks:  []string{"spring", "all"},
			cweIDs:      []string{"CWE-915"},
			tags:        []string{"sast", "mass-assignment", "spring", "java", "owasp-a01"},
			checkInstruction: "Search for Spring controllers vulnerable to mass assignment: " +
				"1) @ModelAttribute or @RequestBody bound to entity classes with sensitive fields (role, isAdmin, balance, password). " +
				"2) Missing @InitBinder with setAllowedFields() or setDisallowedFields(). " +
				"3) Entity classes used directly as DTOs without field restrictions. " +
				"4) Missing @JsonIgnore on sensitive fields when using @RequestBody. " +
				"Flag controllers that bind request data to entities with unrestricted fields.",
			remediation: "Use separate DTO classes for request binding. Apply @InitBinder to restrict bindable fields. Use @JsonIgnore on sensitive entity fields. Never bind directly to domain entities.",
		},
		{
			id:          "SAST-JAVA-004",
			title:       "Spring Security CSRF Protection Disabled",
			description: "Disabling CSRF protection in Spring Security (csrf().disable()) for non-API endpoints exposes form-based operations to cross-site request forgery attacks.",
			severity:    SeverityMedium,
			category:    CategoryBrokenAccessControl,
			languages:   []string{"java", "kotlin"},
			frameworks:  []string{"spring", "all"},
			cweIDs:      []string{"CWE-352"},
			tags:        []string{"sast", "csrf", "spring", "java", "owasp-a01", "sans-top-25"},
			checkInstruction: "Search for CSRF being disabled in Spring Security configuration: " +
				"1) http.csrf().disable() or csrf(csrf -> csrf.disable()) without justification. " +
				"2) CSRF disabled globally when only needed for specific API endpoints. " +
				"3) Missing CsrfTokenRepository configuration for SPA architectures. " +
				"Flag if CSRF protection is disabled for endpoints that serve HTML forms or use cookie-based authentication.",
			remediation: "Keep CSRF enabled for browser-based form submissions. For SPAs with token-based auth, CSRF can be disabled for API endpoints only. Use CookieCsrfTokenRepository for SPA + session auth combinations.",
		},
		{
			id:          "SAST-JAVA-005",
			title:       "Logging Sensitive Data",
			description: "Logging passwords, tokens, credit card numbers, or PII exposes sensitive data in log files, monitoring systems, and crash dumps accessible to operations teams.",
			severity:    SeverityMedium,
			category:    CategoryExposure,
			languages:   []string{"java", "kotlin"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-532", "CWE-200"},
			tags:        []string{"sast", "logging", "sensitive-data", "java", "owasp-a09"},
			checkInstruction: "Search for sensitive data in log statements: " +
				"1) logger.info/debug/error containing password, token, secret, credit card, SSN variables. " +
				"2) Logging full request bodies that may contain credentials. " +
				"3) Exception messages containing sensitive data in stack traces. " +
				"4) ToString() methods on entities that include sensitive fields. " +
				"Flag if passwords, tokens, or PII could reach log output.",
			remediation: "Never log sensitive fields. Override toString() to exclude secrets. Use structured logging with explicit field selection. Implement log redaction filters. Mark sensitive fields with @ToString.Exclude (Lombok).",
		},
	})
}

func buildCrosslanguageSASTRules() []SecurityRule {
	return buildSASTRulesFromDefinitions([]sastRuleDefinition{
		{
			id:          "SAST-XL-001",
			title:       "Improper Error Handling Exposing Stack Traces",
			description: "Returning stack traces, internal paths, database errors, or framework details in API error responses reveals implementation details that help attackers craft targeted exploits.",
			severity:    SeverityMedium,
			category:    CategoryExposure,
			languages:   []string{"all"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-209", "CWE-200"},
			tags:        []string{"sast", "error-handling", "information-exposure", "owasp-a04"},
			checkInstruction: "Search for error handling that exposes internal details: " +
				"1) Catching exceptions and returning err.message or err.stack directly to clients. " +
				"2) Express error middleware sending error.stack in JSON responses. " +
				"3) Spring @ExceptionHandler returning full exception messages. " +
				"4) Generic 500 error pages showing framework/version info. " +
				"5) Database error messages forwarded to API responses. " +
				"Flag if internal error details (stack traces, file paths, SQL errors) reach end users.",
			remediation: "Return generic error messages to clients (Internal Server Error). Log detailed errors server-side only. Implement custom error handlers that sanitize responses. Use error codes instead of messages.",
		},
		{
			id:          "SAST-XL-002",
			title:       "Insecure Direct Object Reference (IDOR)",
			description: "API endpoints that access resources using user-supplied IDs without verifying the authenticated user owns/has access to that resource enable unauthorized data access.",
			severity:    SeverityHigh,
			category:    CategoryBrokenAccessControl,
			languages:   []string{"all"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-639", "CWE-862"},
			tags:        []string{"sast", "idor", "authorization", "access-control", "owasp-a01", "sans-top-25"},
			checkInstruction: "Search for resource access patterns missing ownership validation: " +
				"1) GET /api/users/:id or /api/orders/:orderId that only check authentication, not authorization. " +
				"2) Database queries like findById(req.params.id) without WHERE user_id = currentUser. " +
				"3) File access using user-provided filenames without access control. " +
				"4) Endpoints accepting resource IDs from request without verifying caller's relationship to that resource. " +
				"Flag any data-access endpoint where the authenticated user's ownership/permission is not verified before returning data.",
			remediation: "Always filter queries by the authenticated user: WHERE user_id = ? AND id = ?. Implement resource-level authorization middleware. Use UUIDs instead of sequential IDs to reduce enumeration.",
		},
		{
			id:          "SAST-XL-003",
			title:       "Missing Security Headers",
			description: "HTTP responses without security headers (Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options) leave the application vulnerable to XSS, clickjacking, and downgrade attacks.",
			severity:    SeverityMedium,
			category:    CategoryMisconfiguration,
			languages:   []string{"all"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-693", "CWE-1021"},
			tags:        []string{"sast", "security-headers", "csp", "hsts", "owasp-a05"},
			checkInstruction: "Check that the application sets essential security headers on responses: " +
				"1) Content-Security-Policy — restricts script/resource sources (prevents XSS). " +
				"2) Strict-Transport-Security — forces HTTPS (prevents downgrade). " +
				"3) X-Content-Type-Options: nosniff — prevents MIME sniffing. " +
				"4) X-Frame-Options: DENY or SAMEORIGIN — prevents clickjacking. " +
				"5) Referrer-Policy — controls referrer information leakage. " +
				"6) Permissions-Policy — restricts browser features. " +
				"Check middleware configuration (helmet for Express, SecurityHeaders for Spring, secure_headers for Rails). Flag missing headers.",
			remediation: "Add security headers middleware (helmet.js for Node, Spring Security headers(), Django SecurityMiddleware). Set CSP, HSTS with max-age >= 31536000, X-Content-Type-Options: nosniff, X-Frame-Options: DENY.",
		},
		{
			id:          "SAST-XL-004",
			title:       "Timing Attack in Authentication Comparison",
			description: "Using == or === to compare passwords, tokens, or hashes allows timing attacks where response time differences reveal correct characters. Use constant-time comparison.",
			severity:    SeverityMedium,
			category:    CategoryAuthFailure,
			languages:   []string{"all"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-208"},
			tags:        []string{"sast", "timing-attack", "authentication", "comparison"},
			checkInstruction: "Search for non-constant-time comparisons of secrets: " +
				"1) if (token === storedToken) or if token == expected_token. " +
				"2) String equality checks for API keys, HMAC signatures, password hashes. " +
				"3) Missing crypto.timingSafeEqual (Node), hmac.compare_digest (Python), subtle.ConstantTimeCompare (Go). " +
				"Flag any equality comparison of authentication tokens, API keys, or HMAC signatures that doesn't use a constant-time function.",
			remediation: "Use crypto.timingSafeEqual() in Node.js, hmac.compare_digest() in Python, subtle.ConstantTimeCompare() in Go, or MessageDigest.isEqual() in Java for all secret comparisons.",
		},
		{
			id:          "SAST-XL-005",
			title:       "Use of Insufficiently Random Values for Security",
			description: "Using Math.random(), random.random(), or rand() for generating security tokens, session IDs, or passwords produces predictable values that attackers can guess.",
			severity:    SeverityHigh,
			category:    CategoryInsecureCrypto,
			languages:   []string{"all"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-330", "CWE-338"},
			tags:        []string{"sast", "random", "predictable", "cryptography", "owasp-a02"},
			checkInstruction: "Search for insecure random number generation in security contexts: " +
				"1) Math.random() used for tokens, session IDs, or OTP generation (JavaScript). " +
				"2) random.random() or random.randint() for security purposes (Python — use secrets module). " +
				"3) rand() or mt_rand() in PHP for tokens. " +
				"4) Math.random or ThreadLocalRandom for security in Java (use SecureRandom). " +
				"5) math/rand in Go for security (use crypto/rand). " +
				"Flag if non-cryptographic random is used for any security-sensitive value generation.",
			remediation: "Use crypto.randomBytes/randomUUID (Node.js), secrets.token_hex/token_urlsafe (Python), crypto/rand (Go), SecureRandom (Java), random_bytes (PHP) for all security-sensitive random values.",
		},
		{
			id:          "SAST-XL-006",
			title:       "Password Stored Without Proper Hashing",
			description: "Storing passwords with fast hash algorithms (MD5, SHA-1, SHA-256) or without salt allows efficient brute-force and rainbow table attacks. Use adaptive hashing.",
			severity:    SeverityHigh,
			category:    CategoryInsecureCrypto,
			languages:   []string{"all"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-916", "CWE-328"},
			tags:        []string{"sast", "password-hashing", "bcrypt", "argon2", "owasp-a02"},
			checkInstruction: "Search for password storage patterns: " +
				"1) hashlib.sha256(password) or md5(password) — fast hashes unsuitable for passwords. " +
				"2) crypto.createHash('sha256').update(password) without bcrypt/argon2. " +
				"3) Missing salt in password hashing. " +
				"4) Custom password hashing instead of using established libraries. " +
				"5) Storing passwords in plaintext in databases or configuration. " +
				"Flag any password storage not using bcrypt (cost >= 12), argon2id, or scrypt.",
			remediation: "Use bcrypt with cost factor >= 12, argon2id, or scrypt for password hashing. Never use MD5/SHA for passwords. Libraries: bcryptjs (Node), passlib/argon2 (Python), golang.org/x/crypto/bcrypt (Go), BCryptPasswordEncoder (Spring).",
		},
		{
			id:          "SAST-XL-007",
			title:       "HTTP Response Splitting / CRLF Injection",
			description: "User input reflected in HTTP headers without stripping CR/LF characters allows attackers to inject headers, set cookies, or create split responses for cache poisoning.",
			severity:    SeverityMedium,
			category:    CategoryInjection,
			languages:   []string{"all"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-113", "CWE-93"},
			tags:        []string{"sast", "crlf-injection", "header-injection", "owasp-a03"},
			checkInstruction: "Search for user input flowing into HTTP response headers: " +
				"1) res.setHeader('Location', userInput) or res.setHeader('X-Custom', req.query.value). " +
				"2) Set-Cookie with user-controlled values without CRLF stripping. " +
				"3) redirect(userInput) where input may contain \\r\\n. " +
				"4) Any header value derived from request parameters. " +
				"Flag if user input is used in response headers without stripping \\r and \\n characters.",
			remediation: "Strip or reject CR (\\r) and LF (\\n) characters from any user input used in HTTP headers. Most modern frameworks do this automatically, but verify custom header operations.",
		},
		{
			id:          "SAST-XL-008",
			title:       "Zip Slip - Arbitrary File Write via Archive Extraction",
			description: "Extracting zip/tar archives without validating entry paths allows malicious archives to write files outside the target directory using ../../ sequences, overwriting critical files.",
			severity:    SeverityHigh,
			category:    CategoryInjection,
			languages:   []string{"all"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-22"},
			tags:        []string{"sast", "zip-slip", "path-traversal", "archive", "owasp-a01", "sans-top-25"},
			checkInstruction: "Search for archive extraction that doesn't validate file paths: " +
				"1) zip/tar extraction using entry names directly without checking for ../ sequences. " +
				"2) Go: zip.File.Name joined with target dir without filepath.Rel validation. " +
				"3) Python: zipfile.extractall() without custom member validation (safe in Python 3.12+). " +
				"4) Node: adm-zip, yauzl, tar extraction without path checking. " +
				"5) Java: ZipInputStream without entry path validation. " +
				"Flag archive extraction where entry paths aren't validated to stay within the target directory.",
			remediation: "After joining the entry name with the target directory, verify the resolved path starts with the target directory prefix. Reject entries containing ../ or absolute paths. Use secure extraction libraries.",
		},
		{
			id:          "SAST-XL-009",
			title:       "Cleartext Transmission of Sensitive Data",
			description: "Sending authentication credentials, tokens, or sensitive data over unencrypted HTTP connections allows network-level interception and credential theft.",
			severity:    SeverityHigh,
			category:    CategoryInsecureCrypto,
			languages:   []string{"all"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-319"},
			tags:        []string{"sast", "cleartext", "http", "encryption", "owasp-a02"},
			checkInstruction: "Search for sensitive data transmitted over HTTP: " +
				"1) API calls using http:// URLs for authentication/payment endpoints. " +
				"2) Login forms posting to http:// action URLs. " +
				"3) Webhook configurations using http:// callback URLs for sensitive data. " +
				"4) Internal service communication without TLS for sensitive operations. " +
				"5) Email sending with SMTP without STARTTLS. " +
				"Flag if credentials, tokens, or PII are transmitted over unencrypted channels.",
			remediation: "Use HTTPS for all sensitive communications. Enforce HSTS headers. Configure secure URLs in all service integrations. Use TLS for internal service communication when handling sensitive data.",
		},
		{
			id:          "SAST-XL-010",
			title:       "Unvalidated File Upload",
			description: "File upload endpoints that don't validate file type (by content/magic bytes), size, and filename allow uploading malicious files (web shells, malware) that may be executed by the server.",
			severity:    SeverityHigh,
			category:    CategoryInjection,
			languages:   []string{"all"},
			frameworks:  []string{"all"},
			cweIDs:      []string{"CWE-434"},
			tags:        []string{"sast", "file-upload", "web-shell", "validation", "owasp-a01", "sans-top-25"},
			checkInstruction: "Search for file upload handling and verify: " +
				"1) File type validation by content (magic bytes), not just extension or Content-Type header. " +
				"2) File size limits enforced server-side. " +
				"3) Uploaded filenames sanitized (strip path separators, use UUID names). " +
				"4) Upload directory outside webroot or with execution disabled. " +
				"5) Antivirus/malware scanning for uploaded files. " +
				"Flag if file uploads lack content-type validation, size limits, or are stored in executable locations.",
			remediation: "Validate file content with magic bytes, limit file size, rename files to UUIDs, store outside webroot with execution disabled, scan for malware, and serve through a CDN/proxy without execution.",
		},
	})
}
