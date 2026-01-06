package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/projectdiscovery/httpx/runner"
)

func init() {
	Register(MySQL, newMySQLDatabase)
}

type mysqlDatabase struct {
	cfg *Config
	db  *sql.DB
}

func newMySQLDatabase(cfg *Config) (Database, error) {
	return &mysqlDatabase{cfg: cfg}, nil
}

func (m *mysqlDatabase) Connect(ctx context.Context) error {
	db, err := sql.Open("mysql", m.cfg.ConnectionString)
	if err != nil {
		return fmt.Errorf("failed to open MySQL connection: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping MySQL: %w", err)
	}

	m.db = db
	return nil
}

func (m *mysqlDatabase) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

func (m *mysqlDatabase) EnsureSchema(ctx context.Context) error {
	schema := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,

			-- Basic info
			timestamp DATETIME(6),
			url TEXT,
			input TEXT,
			host VARCHAR(255),
			port VARCHAR(10),
			scheme VARCHAR(10),
			path TEXT,
			method VARCHAR(10),
			final_url TEXT,

			-- Response data
			status_code INT,
			content_length INT,
			content_type VARCHAR(255),
			title TEXT,
			webserver VARCHAR(255),
			response_time VARCHAR(50),
			location TEXT,
			body LONGTEXT,
			body_preview TEXT,
			raw_header LONGTEXT,
			request LONGTEXT,

			-- Network info
			host_ip VARCHAR(45),
			a JSON,
			aaaa JSON,
			cname JSON,
			resolvers JSON,
			body_fqdn JSON,
			body_domains JSON,
			sni TEXT,

			-- Technology detection
			tech JSON,

			-- Hashes and fingerprints
			hash JSON,
			favicon VARCHAR(100),
			favicon_md5 VARCHAR(32),
			favicon_path TEXT,
			favicon_url TEXT,
			jarm_hash VARCHAR(62),

			-- CDN info
			cdn BOOLEAN,
			cdn_name VARCHAR(100),
			cdn_type VARCHAR(50),

			-- ASN info
			asn JSON,

			-- TLS data
			tls JSON,

			-- CSP data
			csp JSON,

			-- Status flags
			failed BOOLEAN,
			error TEXT,
			websocket BOOLEAN,
			http2 BOOLEAN,
			pipeline BOOLEAN,
			vhost BOOLEAN,

			-- Metrics
			words INT,
			` + "`lines`" + ` INT,

			-- Headers and extracts
			header JSON,
			extracts JSON,
			extract_regex JSON,

			-- Chain data
			chain JSON,
			chain_status_codes JSON,

			-- Headless/Screenshot
			headless_body LONGTEXT,
			screenshot_bytes LONGBLOB,
			screenshot_path TEXT,
			screenshot_path_rel TEXT,
			stored_response_path TEXT,

			-- Knowledge base
			knowledgebase JSON,

			-- Link requests
			link_request JSON,

			-- Trace
			trace JSON,

			INDEX idx_timestamp (timestamp),
			INDEX idx_host (host),
			INDEX idx_status_code (status_code)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
	`, m.cfg.TableName)

	_, err := m.db.ExecContext(ctx, schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

func (m *mysqlDatabase) InsertBatch(ctx context.Context, results []runner.Result) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	query := fmt.Sprintf(`
		INSERT INTO %s (
			timestamp, url, input, host, port, scheme, path, method, final_url,
			status_code, content_length, content_type, title, webserver, response_time,
			location, body, body_preview, raw_header, request,
			host_ip, a, aaaa, cname, resolvers, body_fqdn, body_domains, sni,
			tech, hash, favicon, favicon_md5, favicon_path, favicon_url, jarm_hash,
			cdn, cdn_name, cdn_type, asn, tls, csp,
			failed, error, websocket, http2, pipeline, vhost,
			words, `+"`lines`"+`, header, extracts, extract_regex,
			chain, chain_status_codes,
			headless_body, screenshot_bytes, screenshot_path, screenshot_path_rel, stored_response_path,
			knowledgebase, link_request, trace
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?,
			?, ?,
			?, ?, ?, ?, ?,
			?, ?, ?
		)`, m.cfg.TableName)

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, r := range results {
		aJSON, _ := json.Marshal(r.A)
		aaaaJSON, _ := json.Marshal(r.AAAA)
		cnameJSON, _ := json.Marshal(r.CNAMEs)
		resolversJSON, _ := json.Marshal(r.Resolvers)
		fqdnJSON, _ := json.Marshal(r.Fqdns)
		domainsJSON, _ := json.Marshal(r.Domains)
		techJSON, _ := json.Marshal(r.Technologies)
		hashJSON, _ := json.Marshal(r.Hashes)
		asnJSON, _ := json.Marshal(r.ASN)
		tlsJSON, _ := json.Marshal(r.TLSData)
		cspJSON, _ := json.Marshal(r.CSPData)
		headerJSON, _ := json.Marshal(r.ResponseHeaders)
		extractsJSON, _ := json.Marshal(r.Extracts)
		extractRegexJSON, _ := json.Marshal(r.ExtractRegex)
		chainJSON, _ := json.Marshal(r.Chain)
		chainStatusJSON, _ := json.Marshal(r.ChainStatusCodes)
		kbJSON, _ := json.Marshal(r.KnowledgeBase)
		linkReqJSON, _ := json.Marshal(r.LinkRequest)
		traceJSON, _ := json.Marshal(r.Trace)

		_, err = stmt.ExecContext(ctx,
			r.Timestamp, r.URL, r.Input, r.Host, r.Port, r.Scheme, r.Path, r.Method, r.FinalURL,
			r.StatusCode, r.ContentLength, r.ContentType, r.Title, r.WebServer, r.ResponseTime,
			r.Location, r.ResponseBody, r.BodyPreview, r.RawHeaders, r.Request,
			r.HostIP, aJSON, aaaaJSON, cnameJSON, resolversJSON, fqdnJSON, domainsJSON, r.SNI,
			techJSON, hashJSON, r.FavIconMMH3, r.FavIconMD5, r.FaviconPath, r.FaviconURL, r.JarmHash,
			r.CDN, r.CDNName, r.CDNType, asnJSON, tlsJSON, cspJSON,
			r.Failed, r.Error, r.WebSocket, r.HTTP2, r.Pipeline, r.VHost,
			r.Words, r.Lines, headerJSON, extractsJSON, extractRegexJSON,
			chainJSON, chainStatusJSON,
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

func (m *mysqlDatabase) Type() DatabaseType {
	return MySQL
}
