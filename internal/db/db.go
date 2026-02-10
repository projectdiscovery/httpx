package db

import (
	"context"
	"fmt"

	"github.com/projectdiscovery/httpx/runner"
)

type DatabaseType string

const (
	MongoDB    DatabaseType = "mongodb"
	PostgreSQL DatabaseType = "postgres"
	MySQL      DatabaseType = "mysql"
)

func (d DatabaseType) String() string {
	return string(d)
}

func (d DatabaseType) IsValid() bool {
	switch d {
	case MongoDB, PostgreSQL, MySQL:
		return true
	default:
		return false
	}
}

type Database interface {
	Connect(ctx context.Context) error

	Close() error

	InsertBatch(ctx context.Context, results []runner.Result) error

	EnsureSchema(ctx context.Context) error

	Type() DatabaseType
}

type databaseFactory func(cfg *Config) (Database, error)

var registry = make(map[DatabaseType]databaseFactory)

func Register(dbType DatabaseType, factory databaseFactory) {
	registry[dbType] = factory
}

func NewDatabase(cfg *Config) (Database, error) {
	if cfg == nil {
		return nil, fmt.Errorf("database configuration is required")
	}

	if !cfg.Type.IsValid() {
		return nil, fmt.Errorf("unsupported database type: %s", cfg.Type)
	}

	factory, ok := registry[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("database type %s is not registered", cfg.Type)
	}

	return factory(cfg)
}

func SupportedDatabases() []DatabaseType {
	return []DatabaseType{MongoDB, PostgreSQL, MySQL}
}
