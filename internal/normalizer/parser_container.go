package normalizer

import "context"

type ContainerParser struct{}

func NewContainerParser() *ContainerParser {
	return &ContainerParser{}
}

func (p *ContainerParser) Name() string {
	return "Container"
}

func (p *ContainerParser) Parse(ctx context.Context) ([]SecurityRule, error) {
	return buildContainerRules(), nil
}

type containerRuleDefinition struct {
	id          string
	title       string
	description string
	severity    string
	cweIDs      []string
	tags        []string
	checkTarget string
}

func buildContainerRules() []SecurityRule {
	definitions := getContainerDefinitions()
	rules := make([]SecurityRule, 0, len(definitions))

	for _, definition := range definitions {
		rule := SecurityRule{
			ID:          definition.id,
			Source:      SourceContainer,
			Category:    CategoryContainerSecurity,
			Severity:    definition.severity,
			Title:       definition.title,
			Description: definition.description,
			CheckInstruction: generateContainerCheckInstruction(
				definition.title,
				definition.checkTarget,
				definition.description,
			),
			Remediation: "Update the Dockerfile or container configuration to follow container security best practices. Apply the principle of least privilege.",
			Languages:   []string{"all"},
			Frameworks:  []string{"docker", "podman", "containerd"},
			Platforms:   []string{"all"},
			AppliesTo:   AppliesToConfig,
			CWEIDs:      definition.cweIDs,
			Tags:        definition.tags,
		}
		rules = append(rules, rule)
	}

	return rules
}

func generateContainerCheckInstruction(title string, checkTarget string, description string) string {
	instruction := "Inspect all Dockerfiles, Containerfiles, and docker-compose files in the project for: " + title + ". "
	instruction += "Specifically check: " + checkTarget + ". "
	instruction += description + " "
	instruction += "If found, flag it and recommend the secure configuration."
	return instruction
}

func getContainerDefinitions() []containerRuleDefinition {
	return []containerRuleDefinition{
		{
			id:          "CTR-001",
			title:       "Container Running as Root User",
			description: "Containers running as root (UID 0) grant the process full privileges inside the container. If a container escape occurs, the attacker gains root on the host. Use USER directive with a non-root user.",
			severity:    SeverityHigh,
			cweIDs:      []string{"CWE-250", "CWE-269"},
			tags:        []string{"container", "docker", "root", "privilege", "owasp-a01"},
			checkTarget: "Dockerfiles without USER instruction, or USER set to root/0. Also check docker-compose with user: root or user: '0'",
		},
		{
			id:          "CTR-002",
			title:       "Using 'latest' Tag for Base Image",
			description: "Using the 'latest' tag or no tag for base images makes builds non-reproducible and can introduce unexpected vulnerabilities. Pin to specific version digests.",
			severity:    SeverityMedium,
			cweIDs:      []string{"CWE-1104"},
			tags:        []string{"container", "docker", "image-tag", "supply-chain", "owasp-a06"},
			checkTarget: "FROM instructions using ':latest' tag or no tag at all (e.g., 'FROM node' instead of 'FROM node:20-alpine')",
		},
		{
			id:          "CTR-003",
			title:       "Using ADD Instead of COPY for Local Files",
			description: "ADD instruction has implicit behaviors (tar extraction, URL fetching) that can introduce security risks. Use COPY for local file copying and explicit tools for downloads.",
			severity:    SeverityLow,
			cweIDs:      []string{"CWE-829"},
			tags:        []string{"container", "docker", "add-vs-copy", "best-practice"},
			checkTarget: "Dockerfiles using ADD for local file/directory copies instead of COPY. ADD is only appropriate for tar extraction",
		},
		{
			id:          "CTR-004",
			title:       "Secrets Passed as Build Arguments",
			description: "Build arguments (ARG) are stored in image layers and can be extracted. Never pass secrets via --build-arg. Use BuildKit secrets mounts (--mount=type=secret) instead.",
			severity:    SeverityHigh,
			cweIDs:      []string{"CWE-200", "CWE-798"},
			tags:        []string{"container", "docker", "secrets", "build-arg", "owasp-a07"},
			checkTarget: "ARG instructions for sensitive values (passwords, tokens, keys), or ENV instructions setting secrets that persist in the image layer",
		},
		{
			id:          "CTR-005",
			title:       "Missing HEALTHCHECK Instruction",
			description: "Containers without HEALTHCHECK cannot be properly monitored by orchestrators. Unhealthy containers may continue receiving traffic instead of being restarted.",
			severity:    SeverityLow,
			cweIDs:      []string{"CWE-693"},
			tags:        []string{"container", "docker", "healthcheck", "availability"},
			checkTarget: "Dockerfiles for production services without any HEALTHCHECK instruction",
		},
		{
			id:          "CTR-006",
			title:       "Exposing Sensitive Ports Without Justification",
			description: "EXPOSE directives for debugging/admin ports (22/SSH, 2375/Docker, 5432/PostgreSQL, 3306/MySQL, 6379/Redis, 27017/MongoDB) in production images increase attack surface.",
			severity:    SeverityMedium,
			cweIDs:      []string{"CWE-668"},
			tags:        []string{"container", "docker", "ports", "network", "owasp-a05"},
			checkTarget: "EXPOSE instructions for ports 22, 2375, 2376, 5432, 3306, 6379, 27017, 9200 in production Dockerfiles",
		},
		{
			id:          "CTR-007",
			title:       "Package Manager Cache Not Cleaned",
			description: "Leaving package manager caches (apt lists, pip cache, npm cache) in the image increases image size and may contain vulnerability metadata. Clean caches in the same RUN layer.",
			severity:    SeverityLow,
			cweIDs:      []string{"CWE-459"},
			tags:        []string{"container", "docker", "image-size", "cache", "best-practice"},
			checkTarget: "RUN instructions with apt-get install without 'rm -rf /var/lib/apt/lists/*' in the same layer, or pip install without --no-cache-dir",
		},
		{
			id:          "CTR-008",
			title:       "Docker Socket Mounted in Container",
			description: "Mounting /var/run/docker.sock gives the container full control over the Docker daemon, enabling container escape and host compromise. This is equivalent to root access on the host.",
			severity:    SeverityCritical,
			cweIDs:      []string{"CWE-250", "CWE-269"},
			tags:        []string{"container", "docker", "socket", "privilege-escalation", "owasp-a01"},
			checkTarget: "docker-compose volumes mounting /var/run/docker.sock, or docker run commands with -v /var/run/docker.sock",
		},
		{
			id:          "CTR-009",
			title:       "Container with Excessive Capabilities",
			description: "Containers with --cap-add=ALL or --privileged or SYS_ADMIN capability can perform privileged operations. Drop all capabilities and add only those explicitly needed.",
			severity:    SeverityHigh,
			cweIDs:      []string{"CWE-250", "CWE-269"},
			tags:        []string{"container", "docker", "capabilities", "privilege", "owasp-a01"},
			checkTarget: "docker-compose cap_add: [ALL] or [SYS_ADMIN], or privileged: true. Also check for missing cap_drop: [ALL] with explicit cap_add",
		},
		{
			id:          "CTR-010",
			title:       "Writable Root Filesystem in Container",
			description: "Containers with writable root filesystem allow attackers to modify binaries, plant malware, or tamper with configuration. Use read_only: true and explicit tmpfs mounts.",
			severity:    SeverityMedium,
			cweIDs:      []string{"CWE-732"},
			tags:        []string{"container", "docker", "filesystem", "immutable", "owasp-a05"},
			checkTarget: "docker-compose services without read_only: true, or Kubernetes pods without readOnlyRootFilesystem: true",
		},
		{
			id:          "CTR-011",
			title:       "Using Distroless or Minimal Base Image Not Enforced",
			description: "Full OS images (ubuntu, debian, centos) include shells, package managers, and utilities that attackers can leverage post-compromise. Use distroless or alpine-based minimal images.",
			severity:    SeverityLow,
			cweIDs:      []string{"CWE-1104"},
			tags:        []string{"container", "docker", "base-image", "minimal", "attack-surface"},
			checkTarget: "FROM instructions using full OS images like ubuntu, debian, centos, fedora for production runtime stages (not build stages)",
		},
		{
			id:          "CTR-012",
			title:       "COPY with Broad Glob Pattern",
			description: "COPY . . or COPY * copies the entire build context including potential secrets (.env, .git, credentials). Use .dockerignore and specific COPY paths.",
			severity:    SeverityMedium,
			cweIDs:      []string{"CWE-200"},
			tags:        []string{"container", "docker", "copy", "secrets", "information-exposure", "owasp-a01"},
			checkTarget: "'COPY . .' or 'COPY * .' instructions, especially when .dockerignore is missing or doesn't exclude sensitive files",
		},
		{
			id:          "CTR-013",
			title:       "Missing .dockerignore File",
			description: "Without .dockerignore, the entire project directory (including .git, .env, node_modules, secrets) is sent as build context and may be inadvertently included in the image.",
			severity:    SeverityMedium,
			cweIDs:      []string{"CWE-200"},
			tags:        []string{"container", "docker", "dockerignore", "information-exposure", "owasp-a01"},
			checkTarget: "Projects with Dockerfile but no .dockerignore file, or .dockerignore that doesn't exclude .env, .git, and credential files",
		},
		{
			id:          "CTR-014",
			title:       "No Security Scanning in Container Build Pipeline",
			description: "Container images should be scanned for known vulnerabilities before deployment. Integrate Trivy, Grype, or Snyk Container in CI/CD.",
			severity:    SeverityMedium,
			cweIDs:      []string{"CWE-1104"},
			tags:        []string{"container", "docker", "scanning", "ci-cd", "supply-chain", "owasp-a06"},
			checkTarget: "CI/CD pipeline configurations (GitHub Actions, GitLab CI) without a container vulnerability scanning step before deployment",
		},
		{
			id:          "CTR-015",
			title:       "Container with Host Network Mode",
			description: "Containers using host network mode (network_mode: host) share the host's network namespace, bypassing container network isolation and exposing all host ports.",
			severity:    SeverityHigh,
			cweIDs:      []string{"CWE-668"},
			tags:        []string{"container", "docker", "network", "isolation", "owasp-a01"},
			checkTarget: "docker-compose with network_mode: host, or docker run with --network=host",
		},
	}
}
