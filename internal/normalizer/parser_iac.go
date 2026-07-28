package normalizer

import "context"

type IaCParser struct{}

func NewIaCParser() *IaCParser {
	return &IaCParser{}
}

func (p *IaCParser) Name() string {
	return "IaC"
}

func (p *IaCParser) Parse(ctx context.Context) ([]SecurityRule, error) {
	return buildIaCRules(), nil
}

type iacRuleDefinition struct {
	id          string
	title       string
	description string
	severity    string
	platforms   []string
	cweIDs      []string
	tags        []string
	checkTarget string
}

func buildIaCRules() []SecurityRule {
	definitions := getIaCDefinitions()
	rules := make([]SecurityRule, 0, len(definitions))

	for _, definition := range definitions {
		rule := SecurityRule{
			ID:          definition.id,
			Source:      SourceIaC,
			Category:    CategoryIaCMisconfiguration,
			Severity:    definition.severity,
			Title:       definition.title,
			Description: definition.description,
			CheckInstruction: generateIaCCheckInstruction(
				definition.title,
				definition.checkTarget,
				definition.description,
			),
			Remediation: "Fix the infrastructure configuration to follow security best practices. Apply the principle of least privilege and ensure encryption at rest and in transit.",
			Languages:   []string{"all"},
			Frameworks:  []string{"terraform", "cloudformation", "pulumi", "kubernetes"},
			Platforms:   definition.platforms,
			AppliesTo:   AppliesToInfrastructure,
			CWEIDs:      definition.cweIDs,
			Tags:        definition.tags,
		}
		rules = append(rules, rule)
	}

	return rules
}

func generateIaCCheckInstruction(title string, checkTarget string, description string) string {
	instruction := "Inspect all Infrastructure as Code files (Terraform .tf, CloudFormation .yaml/.json, Kubernetes manifests, Pulumi code) for: " + title + ". "
	instruction += "Specifically look in: " + checkTarget + ". "
	instruction += description + " "
	instruction += "If the misconfiguration is found, flag it and recommend the secure alternative."
	return instruction
}

func getIaCDefinitions() []iacRuleDefinition {
	return []iacRuleDefinition{
		{
			id:          "IAC-001",
			title:       "S3 Bucket with Public ACL",
			description: "AWS S3 buckets configured with 'public-read', 'public-read-write', or 'authenticated-read' ACLs expose data to unauthorized access. All buckets should use private ACLs with explicit access policies.",
			severity:    SeverityHigh,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-284", "CWE-732"},
			tags:        []string{"iac", "terraform", "aws", "s3", "public-access", "owasp-a01"},
			checkTarget: "aws_s3_bucket or aws_s3_bucket_acl resources with acl set to 'public-read' or 'public-read-write'",
		},
		{
			id:          "IAC-002",
			title:       "Security Group with Unrestricted Ingress (0.0.0.0/0)",
			description: "Security groups allowing inbound traffic from 0.0.0.0/0 (all IPs) on sensitive ports (SSH/22, RDP/3389, DB ports) expose services to the entire internet.",
			severity:    SeverityHigh,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-284", "CWE-668"},
			tags:        []string{"iac", "terraform", "aws", "security-group", "network", "owasp-a01"},
			checkTarget: "aws_security_group or aws_security_group_rule resources with cidr_blocks containing '0.0.0.0/0' on non-HTTPS ports",
		},
		{
			id:          "IAC-003",
			title:       "RDS Instance Publicly Accessible",
			description: "RDS database instances with publicly_accessible set to true are reachable from the internet, significantly increasing attack surface for database exploits.",
			severity:    SeverityHigh,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-284", "CWE-668"},
			tags:        []string{"iac", "terraform", "aws", "rds", "database", "public-access", "owasp-a01"},
			checkTarget: "aws_db_instance resources with publicly_accessible = true",
		},
		{
			id:          "IAC-004",
			title:       "IAM Policy with Wildcard Action (*)",
			description: "IAM policies granting Action: '*' provide unrestricted access to all AWS services. Apply the principle of least privilege by specifying exact actions needed.",
			severity:    SeverityHigh,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-250", "CWE-269"},
			tags:        []string{"iac", "terraform", "aws", "iam", "privilege-escalation", "owasp-a01"},
			checkTarget: "aws_iam_policy or aws_iam_role_policy with Effect:Allow and Action:'*' or Resource:'*'",
		},
		{
			id:          "IAC-005",
			title:       "EBS Volume Unencrypted",
			description: "EBS volumes without encryption at rest expose data if physical media is compromised or snapshots are shared. Enable encryption using AWS KMS.",
			severity:    SeverityMedium,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-311"},
			tags:        []string{"iac", "terraform", "aws", "ebs", "encryption", "owasp-a02"},
			checkTarget: "aws_ebs_volume or aws_instance root_block_device with encrypted = false or missing",
		},
		{
			id:          "IAC-006",
			title:       "EC2 Instance with IMDSv1 Enabled (SSRF Risk)",
			description: "EC2 instances using IMDSv1 are vulnerable to SSRF attacks that can steal instance credentials. Require IMDSv2 (http_tokens = required).",
			severity:    SeverityMedium,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-918"},
			tags:        []string{"iac", "terraform", "aws", "ec2", "ssrf", "imds", "owasp-a10"},
			checkTarget: "aws_instance metadata_options with http_tokens != 'required' or metadata_options block missing",
		},
		{
			id:          "IAC-007",
			title:       "EKS Cluster with Public API Endpoint",
			description: "EKS clusters with public endpoint enabled allow the Kubernetes API to be reached from the internet. Disable public access or restrict with CIDR blocks.",
			severity:    SeverityMedium,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-284", "CWE-668"},
			tags:        []string{"iac", "terraform", "aws", "eks", "kubernetes", "public-access", "owasp-a01"},
			checkTarget: "aws_eks_cluster with vpc_config endpoint_public_access = true without public_access_cidrs restriction",
		},
		{
			id:          "IAC-008",
			title:       "Terraform Provider with Hardcoded Static Credentials",
			description: "AWS provider blocks with hardcoded access_key and secret_key instead of using assumed roles, environment variables, or instance profiles.",
			severity:    SeverityCritical,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-798"},
			tags:        []string{"iac", "terraform", "aws", "credentials", "hardcoded", "owasp-a07"},
			checkTarget: "provider 'aws' blocks with access_key or secret_key attributes set to literal strings",
		},
		{
			id:          "IAC-009",
			title:       "CloudTrail Logging Disabled",
			description: "AWS CloudTrail not configured or disabled means no audit trail of API activity. Enable multi-region CloudTrail with log file validation.",
			severity:    SeverityHigh,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-778"},
			tags:        []string{"iac", "terraform", "aws", "cloudtrail", "logging", "audit", "owasp-a09"},
			checkTarget: "Missing aws_cloudtrail resource, or is_multi_region_trail = false, or enable_log_file_validation = false",
		},
		{
			id:          "IAC-010",
			title:       "S3 Bucket Without Server-Side Encryption",
			description: "S3 buckets without default server-side encryption configured. Data stored without encryption is at risk if access controls are bypassed.",
			severity:    SeverityMedium,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-311"},
			tags:        []string{"iac", "terraform", "aws", "s3", "encryption", "owasp-a02"},
			checkTarget: "aws_s3_bucket without aws_s3_bucket_server_side_encryption_configuration or server_side_encryption_configuration block",
		},
		{
			id:          "IAC-011",
			title:       "GCP Compute Instance with Default Service Account",
			description: "GCP instances using the default service account often have excessive permissions. Create and assign a custom service account with minimal roles.",
			severity:    SeverityMedium,
			platforms:   []string{"gcp"},
			cweIDs:      []string{"CWE-250", "CWE-269"},
			tags:        []string{"iac", "terraform", "gcp", "compute", "service-account", "owasp-a01"},
			checkTarget: "google_compute_instance without service_account block or using '-compute@developer.gserviceaccount.com'",
		},
		{
			id:          "IAC-012",
			title:       "GCP Storage Bucket with Uniform Bucket Access Disabled",
			description: "GCP Cloud Storage buckets without uniform bucket-level access use legacy ACLs that are harder to audit and more prone to misconfiguration.",
			severity:    SeverityMedium,
			platforms:   []string{"gcp"},
			cweIDs:      []string{"CWE-284"},
			tags:        []string{"iac", "terraform", "gcp", "storage", "access-control", "owasp-a01"},
			checkTarget: "google_storage_bucket with uniform_bucket_level_access = false or not set",
		},
		{
			id:          "IAC-013",
			title:       "Azure Storage Account Allows HTTP Access",
			description: "Azure Storage accounts with enable_https_traffic_only = false allow unencrypted HTTP traffic, enabling man-in-the-middle attacks.",
			severity:    SeverityHigh,
			platforms:   []string{"azure"},
			cweIDs:      []string{"CWE-319"},
			tags:        []string{"iac", "terraform", "azure", "storage", "encryption", "owasp-a02"},
			checkTarget: "azurerm_storage_account with enable_https_traffic_only = false or https_traffic_only_enabled = false",
		},
		{
			id:          "IAC-014",
			title:       "Kubernetes Pod Running as Root",
			description: "Kubernetes pods/containers configured to run as root (runAsUser: 0 or runAsNonRoot: false) violate the principle of least privilege.",
			severity:    SeverityHigh,
			platforms:   []string{"kubernetes"},
			cweIDs:      []string{"CWE-250", "CWE-269"},
			tags:        []string{"iac", "kubernetes", "k8s", "container", "privilege", "owasp-a01"},
			checkTarget: "Pod/Deployment spec with securityContext.runAsUser: 0, or missing runAsNonRoot: true in containers",
		},
		{
			id:          "IAC-015",
			title:       "Kubernetes Pod with Privileged Container",
			description: "Containers running in privileged mode have full access to the host's resources, enabling container escape and host compromise.",
			severity:    SeverityCritical,
			platforms:   []string{"kubernetes"},
			cweIDs:      []string{"CWE-250", "CWE-269"},
			tags:        []string{"iac", "kubernetes", "k8s", "container", "privilege-escalation", "owasp-a01"},
			checkTarget: "Pod/Deployment spec containers with securityContext.privileged: true",
		},
		{
			id:          "IAC-016",
			title:       "Kubernetes Service of Type LoadBalancer Without Restrictions",
			description: "LoadBalancer services without loadBalancerSourceRanges expose the service to all internet traffic. Restrict to known CIDR ranges.",
			severity:    SeverityMedium,
			platforms:   []string{"kubernetes"},
			cweIDs:      []string{"CWE-284", "CWE-668"},
			tags:        []string{"iac", "kubernetes", "k8s", "network", "public-access", "owasp-a01"},
			checkTarget: "Service type: LoadBalancer without spec.loadBalancerSourceRanges",
		},
		{
			id:          "IAC-017",
			title:       "Kubernetes Secret in Environment Variable Instead of Volume Mount",
			description: "Secrets passed via environment variables can leak through process listings, logs, and crash dumps. Mount secrets as files instead.",
			severity:    SeverityMedium,
			platforms:   []string{"kubernetes"},
			cweIDs:      []string{"CWE-200", "CWE-532"},
			tags:        []string{"iac", "kubernetes", "k8s", "secrets", "information-exposure", "owasp-a04"},
			checkTarget: "Pod/Deployment containers with env[].valueFrom.secretKeyRef instead of volumeMounts with secret volumes",
		},
		{
			id:          "IAC-018",
			title:       "Kubernetes NetworkPolicy Missing (Default Allow All)",
			description: "Namespaces without NetworkPolicy resources allow all pod-to-pod communication by default. Apply deny-all ingress/egress policies with explicit allowlists.",
			severity:    SeverityMedium,
			platforms:   []string{"kubernetes"},
			cweIDs:      []string{"CWE-284"},
			tags:        []string{"iac", "kubernetes", "k8s", "network", "isolation", "owasp-a01"},
			checkTarget: "Kubernetes namespaces without any NetworkPolicy resource, or pods without matching NetworkPolicy selectors",
		},
		{
			id:          "IAC-019",
			title:       "RDS Instance Without Encryption at Rest",
			description: "RDS instances with storage_encrypted = false store data unencrypted on disk, violating data protection requirements.",
			severity:    SeverityMedium,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-311"},
			tags:        []string{"iac", "terraform", "aws", "rds", "encryption", "owasp-a02"},
			checkTarget: "aws_db_instance with storage_encrypted = false or not set",
		},
		{
			id:          "IAC-020",
			title:       "Lambda Function Without VPC Configuration",
			description: "Lambda functions without VPC configuration can access the internet directly, potentially exposing internal resources or enabling data exfiltration.",
			severity:    SeverityLow,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-668"},
			tags:        []string{"iac", "terraform", "aws", "lambda", "network", "owasp-a05"},
			checkTarget: "aws_lambda_function without vpc_config block when the function accesses internal resources",
		},
		{
			id:          "IAC-021",
			title:       "Azure App Service with Remote Debugging Enabled",
			description: "Remote debugging left enabled on Azure App Services opens debugging ports and should only be used during development.",
			severity:    SeverityMedium,
			platforms:   []string{"azure"},
			cweIDs:      []string{"CWE-489"},
			tags:        []string{"iac", "terraform", "azure", "app-service", "debug", "owasp-a05"},
			checkTarget: "azurerm_app_service or azurerm_linux_web_app with site_config.remote_debugging_enabled = true",
		},
		{
			id:          "IAC-022",
			title:       "ElastiCache Redis Without Encryption in Transit",
			description: "Redis clusters without transit_encryption_enabled allow data to be intercepted between application and cache layer.",
			severity:    SeverityMedium,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-319"},
			tags:        []string{"iac", "terraform", "aws", "elasticache", "redis", "encryption", "owasp-a02"},
			checkTarget: "aws_elasticache_replication_group with transit_encryption_enabled = false or not set",
		},
		{
			id:          "IAC-023",
			title:       "VPC Flow Logs Disabled",
			description: "VPCs without flow logs configured lack network traffic audit trails, making incident investigation and anomaly detection impossible.",
			severity:    SeverityMedium,
			platforms:   []string{"aws"},
			cweIDs:      []string{"CWE-778"},
			tags:        []string{"iac", "terraform", "aws", "vpc", "logging", "owasp-a09"},
			checkTarget: "aws_vpc without corresponding aws_flow_log resource",
		},
		{
			id:          "IAC-024",
			title:       "GKE Cluster with Legacy ABAC Enabled",
			description: "GKE clusters with enable_legacy_abac = true bypass RBAC controls, allowing any authenticated user full cluster access.",
			severity:    SeverityHigh,
			platforms:   []string{"gcp"},
			cweIDs:      []string{"CWE-269", "CWE-284"},
			tags:        []string{"iac", "terraform", "gcp", "gke", "kubernetes", "access-control", "owasp-a01"},
			checkTarget: "google_container_cluster with enable_legacy_abac = true",
		},
	}
}
