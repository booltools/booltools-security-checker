package normalizer

import "fmt"

func GenerateCVECheckInstruction(cveID string, description string, affectedProduct string, affectedVersions string) string {
	instruction := fmt.Sprintf("Check if the project is affected by %s. ", cveID)

	if affectedProduct != "" {
		instruction += fmt.Sprintf("Look for usage of '%s' in dependency files (package.json, go.mod, pom.xml, requirements.txt, Gemfile, Cargo.toml, *.csproj). ", affectedProduct)
	}

	if affectedVersions != "" {
		instruction += fmt.Sprintf("Vulnerable versions: %s. Verify the installed version is not in this range. ", affectedVersions)
	}

	instruction += "If the dependency is found at a vulnerable version, flag it as a security risk and recommend upgrading to the latest patched version."

	return instruction
}

func GenerateCWECheckInstruction(cweID string, cweName string, description string) string {
	return fmt.Sprintf(
		"Analyze the codebase for %s (%s). %s Look for code patterns that match this weakness. Check that appropriate mitigations are in place.",
		cweID, cweName, truncateDescription(description, 200),
	)
}

func GenerateCAPECCheckInstruction(capecID string, name string, description string) string {
	return fmt.Sprintf(
		"Verify the application is protected against %s (%s). %s Check that input validation, access controls, and defensive measures are properly implemented to prevent this attack pattern.",
		capecID, name, truncateDescription(description, 200),
	)
}

func GenerateMITREAttackCheckInstruction(techniqueID string, name string, description string) string {
	return fmt.Sprintf(
		"Assess if the system is vulnerable to technique %s (%s). %s Verify that detection mechanisms, logging, and preventive controls are in place for this technique.",
		techniqueID, name, truncateDescription(description, 200),
	)
}

func GenerateExploitDBCheckInstruction(cveID string, exploitTitle string, platform string) string {
	instruction := fmt.Sprintf("A public exploit exists for %s: '%s'. ", cveID, exploitTitle)

	if platform != "" {
		instruction += fmt.Sprintf("This exploit targets the '%s' platform. ", platform)
	}

	instruction += "Verify the project is not using the affected component at a vulnerable version. Since a public exploit exists, this vulnerability is actively weaponized and should be prioritized for patching."

	return instruction
}

func GenerateKEVCheckInstruction(cveID string, vendorProject string, product string, requiredAction string) string {
	instruction := fmt.Sprintf("CRITICAL: %s is in CISA's Known Exploited Vulnerabilities catalog - confirmed active exploitation in the wild. ", cveID)

	if vendorProject != "" && product != "" {
		instruction += fmt.Sprintf("Affects %s %s. ", vendorProject, product)
	}

	if requiredAction != "" {
		instruction += fmt.Sprintf("Required action: %s ", requiredAction)
	}

	instruction += "Check immediately if this product/version is in use. This is a top-priority remediation item."

	return instruction
}

func GenerateNucleiCheckInstruction(templateID string, name string, description string, severity string) string {
	instruction := fmt.Sprintf("Security check from Nuclei template '%s': %s. ", templateID, name)

	if description != "" {
		instruction += truncateDescription(description, 200) + " "
	}

	instruction += "Verify the application or infrastructure is not vulnerable to this issue. Check server configurations, exposed endpoints, and response headers as applicable."

	return instruction
}

func GenerateGHSACheckInstruction(ghsaID string, summary string, ecosystem string, packageName string, vulnerableRange string) string {
	instruction := fmt.Sprintf("Security advisory %s: %s. ", ghsaID, summary)

	if ecosystem != "" && packageName != "" {
		instruction += fmt.Sprintf("Check if package '%s' (%s ecosystem) is used in the project. ", packageName, ecosystem)
	}

	if vulnerableRange != "" {
		instruction += fmt.Sprintf("Vulnerable version range: %s. ", vulnerableRange)
	}

	instruction += "Verify the project is using a patched version or apply the recommended fix."

	return instruction
}

func GenerateOSVCheckInstruction(osvID string, summary string, ecosystem string, packageName string, affectedRanges string) string {
	instruction := fmt.Sprintf("Open source vulnerability %s: %s. ", osvID, summary)

	if ecosystem != "" && packageName != "" {
		instruction += fmt.Sprintf("Affects package '%s' in the %s ecosystem. ", packageName, ecosystem)
	}

	if affectedRanges != "" {
		instruction += fmt.Sprintf("Affected versions: %s. ", affectedRanges)
	}

	instruction += "Check dependency files to verify the project is not using an affected version."

	return instruction
}

func GenerateSecretsCheckInstruction(title string, pattern string, description string) string {
	instruction := "Search the entire codebase (including configuration files, environment examples, and test files) for " + title + ". "
	instruction += "Look for patterns matching: " + pattern + ". "
	instruction += description + " "
	instruction += "Check .env.example, docker-compose files, CI configs, and source code. If found, flag as a critical security issue requiring immediate rotation of the exposed credential."
	return instruction
}

func GenerateIaCCheckInstruction(title string, checkTarget string, description string) string {
	instruction := "Inspect all Infrastructure as Code files (Terraform .tf, CloudFormation .yaml/.json, Kubernetes manifests, Pulumi code) for: " + title + ". "
	instruction += "Specifically look in: " + checkTarget + ". "
	instruction += description + " "
	instruction += "If the misconfiguration is found, flag it and recommend the secure alternative."
	return instruction
}

func GenerateContainerCheckInstruction(title string, checkTarget string, description string) string {
	instruction := "Inspect all Dockerfiles, Containerfiles, and docker-compose files in the project for: " + title + ". "
	instruction += "Specifically check: " + checkTarget + ". "
	instruction += description + " "
	instruction += "If found, flag it and recommend the secure configuration."
	return instruction
}

func truncateDescription(description string, maxLength int) string {
	if len(description) <= maxLength {
		return description
	}
	return description[:maxLength] + "..."
}
