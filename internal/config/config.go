package config

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port                string
	AllowedOrigins      []string
	AllowAllCORS        bool
	DBUser              string
	DBPassword          string
	DBHost              string
	DBPort              string
	DBName              string
	DSN                 string
	RedisAddr           string
	RedisPassword       string
	AgentScheme         string
	AgentPort           string
	AgentL4Path         string
	AgentL4OptionsPath  string
	AgentToken          string
	AgentTimeoutSeconds int
}

func Load() Config {
	cfg := Config{
		Port:                "8080",
		AllowAllCORS:        true,
		DBUser:              "root",
		DBHost:              "127.0.0.1",
		DBPort:              "3306",
		DBName:              "cdnproxy",
		RedisAddr:           "127.0.0.1:6379",
		RedisPassword:       "",
		AgentScheme:         "http",
		AgentPort:           "5000",
		AgentL4Path:         "/API/L4/l4_firewall_data",
		AgentL4OptionsPath:  "/API/L4/options",
		AgentTimeoutSeconds: 3,
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
	if addr := strings.TrimSpace(os.Getenv("REDIS_ADDR")); addr != "" {
		cfg.RedisAddr = addr
	}
	if os.Getenv("REDIS_PASSWORD") != "" {
		cfg.RedisPassword = os.Getenv("REDIS_PASSWORD")
	}
	if agentScheme := strings.TrimSpace(os.Getenv("AGENT_SCHEME")); agentScheme != "" {
		cfg.AgentScheme = agentScheme
	}
	if agentPort := strings.TrimSpace(os.Getenv("AGENT_PORT")); agentPort != "" {
		cfg.AgentPort = agentPort
	}
	if agentL4Path := strings.TrimSpace(os.Getenv("AGENT_L4_PATH")); agentL4Path != "" {
		cfg.AgentL4Path = agentL4Path
	}
	if agentL4OptionsPath := strings.TrimSpace(os.Getenv("AGENT_L4_OPTIONS_PATH")); agentL4OptionsPath != "" {
		cfg.AgentL4OptionsPath = agentL4OptionsPath
	}
	if os.Getenv("AGENT_TOKEN") != "" {
		cfg.AgentToken = os.Getenv("AGENT_TOKEN")
	}
	if timeoutRaw := strings.TrimSpace(os.Getenv("AGENT_TIMEOUT_SECONDS")); timeoutRaw != "" {
		if parsed, err := strconv.Atoi(timeoutRaw); err == nil && parsed > 0 {
			cfg.AgentTimeoutSeconds = parsed
		}
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
	Port                *string  `json:"port"`
	AllowedOrigins      []string `json:"allowedOrigins"`
	AllowAllCORS        *bool    `json:"allowAllCors"`
	DBUser              *string  `json:"dbUser"`
	DBPassword          *string  `json:"dbPassword"`
	DBHost              *string  `json:"dbHost"`
	DBPort              *string  `json:"dbPort"`
	DBName              *string  `json:"dbName"`
	DSN                 *string  `json:"dsn"`
	RedisAddr           *string  `json:"redisAddr"`
	RedisPassword       *string  `json:"redisPassword"`
	AgentScheme         *string  `json:"agentScheme"`
	AgentPort           *string  `json:"agentPort"`
	AgentL4Path         *string  `json:"agentL4Path"`
	AgentL4OptionsPath  *string  `json:"agentL4OptionsPath"`
	AgentToken          *string  `json:"agentToken"`
	AgentTimeoutSeconds *int     `json:"agentTimeoutSeconds"`
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
	if fileCfg.RedisAddr != nil && strings.TrimSpace(*fileCfg.RedisAddr) != "" {
		cfg.RedisAddr = strings.TrimSpace(*fileCfg.RedisAddr)
	}
	if fileCfg.RedisPassword != nil {
		cfg.RedisPassword = *fileCfg.RedisPassword
	}
	if fileCfg.AgentScheme != nil && strings.TrimSpace(*fileCfg.AgentScheme) != "" {
		cfg.AgentScheme = strings.TrimSpace(*fileCfg.AgentScheme)
	}
	if fileCfg.AgentPort != nil && strings.TrimSpace(*fileCfg.AgentPort) != "" {
		cfg.AgentPort = strings.TrimSpace(*fileCfg.AgentPort)
	}
	if fileCfg.AgentL4Path != nil && strings.TrimSpace(*fileCfg.AgentL4Path) != "" {
		cfg.AgentL4Path = strings.TrimSpace(*fileCfg.AgentL4Path)
	}
	if fileCfg.AgentL4OptionsPath != nil && strings.TrimSpace(*fileCfg.AgentL4OptionsPath) != "" {
		cfg.AgentL4OptionsPath = strings.TrimSpace(*fileCfg.AgentL4OptionsPath)
	}
	if fileCfg.AgentToken != nil {
		cfg.AgentToken = *fileCfg.AgentToken
	}
	if fileCfg.AgentTimeoutSeconds != nil && *fileCfg.AgentTimeoutSeconds > 0 {
		cfg.AgentTimeoutSeconds = *fileCfg.AgentTimeoutSeconds
	}
}
