package db

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultBatchSize = 100

	DefaultFlushInterval = time.Minute

	DefaultTableName = "results"

	DefaultDatabaseName = "httpx"

	EnvConnectionString = "HTTPX_DB_CONNECTION_STRING"
)

type Config struct {
	Type DatabaseType `yaml:"type"`

	ConnectionString string `yaml:"connection-string"`

	DatabaseName string `yaml:"database-name"`

	TableName string `yaml:"table-name"`

	BatchSize int `yaml:"batch-size"`

	FlushInterval time.Duration `yaml:"flush-interval"`

	OmitRaw bool `yaml:"omit-raw"`
}

func (c *Config) Validate() error {
	if !c.Type.IsValid() {
		return fmt.Errorf("invalid database type: %s (supported: %v)", c.Type, SupportedDatabases())
	}

	if c.ConnectionString == "" {
		return fmt.Errorf("connection string is required")
	}

	return nil
}

func (c *Config) ApplyDefaults() {
	if c.DatabaseName == "" {
		c.DatabaseName = DefaultDatabaseName
	}

	if c.TableName == "" {
		c.TableName = DefaultTableName
	}

	if c.BatchSize <= 0 {
		c.BatchSize = DefaultBatchSize
	}

	if c.FlushInterval <= 0 {
		c.FlushInterval = DefaultFlushInterval
	}
}

func LoadConfigFromFile(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if cfg.ConnectionString == "" {
		cfg.ConnectionString = os.Getenv(EnvConnectionString)
	}

	cfg.ApplyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

type Options struct {
	Enabled          bool
	ConfigFile       string
	Type             string
	ConnectionString string
	DatabaseName     string
	TableName        string
	BatchSize        int
	OmitRaw          bool
}

func (o *Options) ToConfig() (*Config, error) {
	cfg := &Config{
		Type:             DatabaseType(o.Type),
		ConnectionString: o.ConnectionString,
		DatabaseName:     o.DatabaseName,
		TableName:        o.TableName,
		BatchSize:        o.BatchSize,
		OmitRaw:          o.OmitRaw,
	}

	if cfg.ConnectionString == "" {
		cfg.ConnectionString = os.Getenv(EnvConnectionString)
	}

	cfg.ApplyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}
