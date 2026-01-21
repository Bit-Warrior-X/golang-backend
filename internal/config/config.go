package config

import (
	"encoding/json"
	"os"
	"strings"
)

type Config struct {
	Port           string
	AllowedOrigins []string
	AllowAllCORS   bool
	DBUser         string
	DBPassword     string
	DBHost         string
	DBPort         string
	DBName         string
	DSN            string
}

func Load() Config {
	cfg := Config{
		Port:         "8080",
		AllowAllCORS: true,
		DBUser:       "root",
		DBHost:       "127.0.0.1",
		DBPort:       "3306",
		DBName:       "cdnproxy",
	}

	configPath := strings.TrimSpace(os.Getenv("CONFIG_FILE"))
	if configPath == "" {
		configPath = "config.json"
	}
	if fileCfg, err := loadFileConfig(configPath); err == nil && fileCfg != nil {
		applyFileConfig(&cfg, *fileCfg)
	}

	if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
		cfg.Port = port
	}
	if dbUser := strings.TrimSpace(os.Getenv("DB_USER")); dbUser != "" {
		cfg.DBUser = dbUser
	}
	if os.Getenv("DB_PASSWORD") != "" {
		cfg.DBPassword = os.Getenv("DB_PASSWORD")
	}
	if dbHost := strings.TrimSpace(os.Getenv("DB_HOST")); dbHost != "" {
		cfg.DBHost = dbHost
	}
	if dbPort := strings.TrimSpace(os.Getenv("DB_PORT")); dbPort != "" {
		cfg.DBPort = dbPort
	}
	if dbName := strings.TrimSpace(os.Getenv("DB_NAME")); dbName != "" {
		cfg.DBName = dbName
	}
	if dsn := strings.TrimSpace(os.Getenv("DB_DSN")); dsn != "" {
		cfg.DSN = dsn
	}

	if origins := strings.TrimSpace(os.Getenv("ALLOWED_ORIGINS")); origins != "" {
		cfg.AllowedOrigins = splitAndTrim(origins)
		cfg.AllowAllCORS = false
	}

	if len(cfg.AllowedOrigins) == 0 && !cfg.AllowAllCORS {
		cfg.AllowAllCORS = true
	}

	return cfg
}

func splitAndTrim(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

type fileConfig struct {
	Port           *string  `json:"port"`
	AllowedOrigins []string `json:"allowedOrigins"`
	AllowAllCORS   *bool    `json:"allowAllCors"`
	DBUser         *string  `json:"dbUser"`
	DBPassword     *string  `json:"dbPassword"`
	DBHost         *string  `json:"dbHost"`
	DBPort         *string  `json:"dbPort"`
	DBName         *string  `json:"dbName"`
	DSN            *string  `json:"dsn"`
}

func loadFileConfig(path string) (*fileConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg fileConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyFileConfig(cfg *Config, fileCfg fileConfig) {
	if fileCfg.Port != nil && strings.TrimSpace(*fileCfg.Port) != "" {
		cfg.Port = strings.TrimSpace(*fileCfg.Port)
	}
	if fileCfg.AllowedOrigins != nil {
		cfg.AllowedOrigins = fileCfg.AllowedOrigins
		if len(fileCfg.AllowedOrigins) > 0 {
			cfg.AllowAllCORS = false
		}
	}
	if fileCfg.AllowAllCORS != nil {
		cfg.AllowAllCORS = *fileCfg.AllowAllCORS
	}
	if fileCfg.DBUser != nil && strings.TrimSpace(*fileCfg.DBUser) != "" {
		cfg.DBUser = strings.TrimSpace(*fileCfg.DBUser)
	}
	if fileCfg.DBPassword != nil {
		cfg.DBPassword = *fileCfg.DBPassword
	}
	if fileCfg.DBHost != nil && strings.TrimSpace(*fileCfg.DBHost) != "" {
		cfg.DBHost = strings.TrimSpace(*fileCfg.DBHost)
	}
	if fileCfg.DBPort != nil && strings.TrimSpace(*fileCfg.DBPort) != "" {
		cfg.DBPort = strings.TrimSpace(*fileCfg.DBPort)
	}
	if fileCfg.DBName != nil && strings.TrimSpace(*fileCfg.DBName) != "" {
		cfg.DBName = strings.TrimSpace(*fileCfg.DBName)
	}
	if fileCfg.DSN != nil && strings.TrimSpace(*fileCfg.DSN) != "" {
		cfg.DSN = strings.TrimSpace(*fileCfg.DSN)
	}
}
