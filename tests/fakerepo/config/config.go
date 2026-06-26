package config

type AppConfig struct {
	Database DatabaseConfig
	Server   ServerConfig
	AWS      AWSConfig
}

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string // set to "disable" in production!
}

type ServerConfig struct {
	Port    int
	TLSCert string
	TLSKey  string
}

type AWSConfig struct {
	Region    string
	AccessKey string
	SecretKey string
	Bucket    string
}

func DefaultConfig() *AppConfig {
	return &AppConfig{
		Database: DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "postgres",
			Password: "postgres123",
			DBName:   "acme_prod",
			SSLMode:  "disable", // CWE-319: cleartext transmission
		},
		Server: ServerConfig{
			Port: 8080,
		},
		AWS: AWSConfig{
			Region:    "us-east-1",
			AccessKey: "AKIAIOSFODNN7EXAMPLE",
			SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Bucket:    "acme-uploads",
		},
	}
}
