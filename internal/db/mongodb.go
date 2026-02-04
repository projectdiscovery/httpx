package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/projectdiscovery/httpx/runner"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func init() {
	Register(MongoDB, newMongoDatabase)
}

type mongoDatabase struct {
	cfg        *Config
	client     *mongo.Client
	database   *mongo.Database
	collection *mongo.Collection
}

func newMongoDatabase(cfg *Config) (Database, error) {
	return &mongoDatabase{cfg: cfg}, nil
}

func (m *mongoDatabase) Connect(ctx context.Context) error {
	clientOpts := options.Client().
		ApplyURI(m.cfg.ConnectionString).
		SetConnectTimeout(10 * time.Second).
		SetServerSelectionTimeout(10 * time.Second)

	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		return fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	m.client = client
	m.database = client.Database(m.cfg.DatabaseName)
	m.collection = m.database.Collection(m.cfg.TableName)

	return nil
}

func (m *mongoDatabase) Close() error {
	if m.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return m.client.Disconnect(ctx)
	}
	return nil
}

func (m *mongoDatabase) EnsureSchema(ctx context.Context) error {
	indexes := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "timestamp", Value: -1}},
		},
		{
			Keys: bson.D{{Key: "url", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "host", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "status_code", Value: 1}},
		},
		{
			Keys:    bson.D{{Key: "tech", Value: 1}},
			Options: options.Index().SetSparse(true),
		},
	}

	_, err := m.collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}

func (m *mongoDatabase) InsertBatch(ctx context.Context, results []runner.Result) error {
	if len(results) == 0 {
		return nil
	}

	documents := make([]interface{}, len(results))
	for i, r := range results {
		doc, err := m.resultToDocument(r)
		if err != nil {
			return fmt.Errorf("failed to convert result to document: %w", err)
		}
		documents[i] = doc
	}

	_, err := m.collection.InsertMany(ctx, documents)
	if err != nil {
		return fmt.Errorf("failed to insert batch: %w", err)
	}

	return nil
}

func (m *mongoDatabase) Type() DatabaseType {
	return MongoDB
}

func (m *mongoDatabase) resultToDocument(r runner.Result) (bson.M, error) {
	jsonBytes, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result to JSON: %w", err)
	}

	var doc bson.M
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to BSON: %w", err)
	}

	return doc, nil
}
