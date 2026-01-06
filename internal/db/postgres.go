package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"
	"github.com/projectdiscovery/httpx/runner"
)

func init() {
	Register(PostgreSQL, newPostgresDatabase)
}

type postgresDatabase struct {
	cfg *Config
	db  *sql.DB
}

func newPostgresDatabase(cfg *Config) (Database, error) {
	return &postgresDatabase{cfg: cfg}, nil
}

func (p *postgresDatabase) Connect(ctx context.Context) error {
	db, err := sql.Open("postgres", p.cfg.ConnectionString)
	if err != nil {
		return fmt.Errorf("failed to open PostgreSQL connection: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	p.db = db
	return nil
}

func (p *postgresDatabase) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

func (p *postgresDatabase) EnsureSchema(ctx context.Context) error {
	tableName := pq.QuoteIdentifier(p.cfg.TableName)
	idxTimestamp := pq.QuoteIdentifier("idx_" + p.cfg.TableName + "_timestamp")
	idxURL := pq.QuoteIdentifier("idx_" + p.cfg.TableName + "_url")
	idxHost := pq.QuoteIdentifier("idx_" + p.cfg.TableName + "_host")
	idxStatusCode := pq.QuoteIdentifier("idx_" + p.cfg.TableName + "_status_code")
	idxTech := pq.QuoteIdentifier("idx_" + p.cfg.TableName + "_tech")

	schema := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id BIGSERIAL PRIMARY KEY,

			-- Basic info
			timestamp TIMESTAMP WITH TIME ZONE,
			url TEXT,
			input TEXT,
			host TEXT,
			port TEXT,
			scheme TEXT,
			path TEXT,
			method TEXT,
			final_url TEXT,

			-- Response data
			status_code INTEGER,
			content_length INTEGER,
			content_type TEXT,
			title TEXT,
			webserver TEXT,
			response_time TEXT,
			location TEXT,
			body TEXT,
			body_preview TEXT,
			raw_header TEXT,
			request TEXT,

			-- Network info
			host_ip TEXT,
			a TEXT[],
			aaaa TEXT[],
			cname TEXT[],
			resolvers TEXT[],
			body_fqdn TEXT[],
			body_domains TEXT[],
			sni TEXT,

			-- Technology detection
			tech TEXT[],

			-- Hashes and fingerprints
			hash JSONB,
			favicon TEXT,
			favicon_md5 TEXT,
			favicon_path TEXT,
			favicon_url TEXT,
			jarm_hash TEXT,

			-- CDN info
			cdn BOOLEAN,
			cdn_name TEXT,
			cdn_type TEXT,

			-- ASN info
			asn JSONB,

			-- TLS data
			tls JSONB,

			-- CSP data
			csp JSONB,

			-- Status flags
			failed BOOLEAN,
			error TEXT,
			websocket BOOLEAN,
			http2 BOOLEAN,
			pipeline BOOLEAN,
			vhost BOOLEAN,

			-- Metrics
			words INTEGER,
			lines INTEGER,

			-- Headers and extracts
			header JSONB,
			extracts JSONB,
			extract_regex TEXT[],

			-- Chain data
			chain JSONB,
			chain_status_codes INTEGER[],

			-- Headless/Screenshot
			headless_body TEXT,
			screenshot_bytes BYTEA,
			screenshot_path TEXT,
			screenshot_path_rel TEXT,
			stored_response_path TEXT,

			-- Knowledge base
			knowledgebase JSONB,

			-- Link requests
			link_request JSONB,

			-- Trace
			trace JSONB
		);

		CREATE INDEX IF NOT EXISTS %s ON %s(timestamp DESC);
		CREATE INDEX IF NOT EXISTS %s ON %s(url);
		CREATE INDEX IF NOT EXISTS %s ON %s(host);
		CREATE INDEX IF NOT EXISTS %s ON %s(status_code);
		CREATE INDEX IF NOT EXISTS %s ON %s USING GIN(tech);
	`,
		tableName,
		idxTimestamp, tableName,
		idxURL, tableName,
		idxHost, tableName,
		idxStatusCode, tableName,
		idxTech, tableName,
	)

	_, err := p.db.ExecContext(ctx, schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

func (p *postgresDatabase) InsertBatch(ctx context.Context, results []runner.Result) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	tableName := pq.QuoteIdentifier(p.cfg.TableName)
	query := fmt.Sprintf(`
		INSERT INTO %s (
			timestamp, url, input, host, port, scheme, path, method, final_url,
			status_code, content_length, content_type, title, webserver, response_time,
			location, body, body_preview, raw_header, request,
			host_ip, a, aaaa, cname, resolvers, body_fqdn, body_domains, sni,
			tech, hash, favicon, favicon_md5, favicon_path, favicon_url, jarm_hash,
			cdn, cdn_name, cdn_type, asn, tls, csp,
			failed, error, websocket, http2, pipeline, vhost,
			words, lines, header, extracts, extract_regex,
			chain, chain_status_codes,
			headless_body, screenshot_bytes, screenshot_path, screenshot_path_rel, stored_response_path,
			knowledgebase, link_request, trace
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9,
			$10, $11, $12, $13, $14, $15,
			$16, $17, $18, $19, $20,
			$21, $22, $23, $24, $25, $26, $27, $28,
			$29, $30, $31, $32, $33, $34, $35,
			$36, $37, $38, $39, $40, $41,
			$42, $43, $44, $45, $46, $47,
			$48, $49, $50, $51, $52,
			$53, $54,
			$55, $56, $57, $58, $59,
			$60, $61, $62
		)`, tableName)

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, r := range results {
		hashJSON, _ := json.Marshal(r.Hashes)
		asnJSON, _ := json.Marshal(r.ASN)
		tlsJSON, _ := json.Marshal(r.TLSData)
		cspJSON, _ := json.Marshal(r.CSPData)
		headerJSON, _ := json.Marshal(r.ResponseHeaders)
		extractsJSON, _ := json.Marshal(r.Extracts)
		chainJSON, _ := json.Marshal(r.Chain)
		kbJSON, _ := json.Marshal(r.KnowledgeBase)
		linkReqJSON, _ := json.Marshal(r.LinkRequest)
		traceJSON, _ := json.Marshal(r.Trace)

		_, err = stmt.ExecContext(ctx,
			r.Timestamp, r.URL, r.Input, r.Host, r.Port, r.Scheme, r.Path, r.Method, r.FinalURL,
			r.StatusCode, r.ContentLength, r.ContentType, r.Title, r.WebServer, r.ResponseTime,
			r.Location, r.ResponseBody, r.BodyPreview, r.RawHeaders, r.Request,
			r.HostIP, pq.Array(r.A), pq.Array(r.AAAA), pq.Array(r.CNAMEs), pq.Array(r.Resolvers), pq.Array(r.Fqdns), pq.Array(r.Domains), r.SNI,
			pq.Array(r.Technologies), hashJSON, r.FavIconMMH3, r.FavIconMD5, r.FaviconPath, r.FaviconURL, r.JarmHash,
			r.CDN, r.CDNName, r.CDNType, asnJSON, tlsJSON, cspJSON,
			r.Failed, r.Error, r.WebSocket, r.HTTP2, r.Pipeline, r.VHost,
			r.Words, r.Lines, headerJSON, extractsJSON, pq.Array(r.ExtractRegex),
			chainJSON, pq.Array(r.ChainStatusCodes),
			r.HeadlessBody, r.ScreenshotBytes, r.ScreenshotPath, r.ScreenshotPathRel, r.StoredResponsePath,
			kbJSON, linkReqJSON, traceJSON,
		)
		if err != nil {
			return fmt.Errorf("failed to insert result: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (p *postgresDatabase) Type() DatabaseType {
	return PostgreSQL
}
