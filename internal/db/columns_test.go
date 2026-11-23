package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/projectdiscovery/httpx/runner"
	"github.com/stretchr/testify/require"
)

// recorder is a database/sql connector that keeps every statement it gets, so
// the SQL writers can be checked without a running database.
type recorder struct {
	queries []string
	args    int // values passed to the last Exec
}

func (r *recorder) Connect(context.Context) (driver.Conn, error) { return &recConn{r}, nil }
func (r *recorder) Driver() driver.Driver                        { return nil }

type recConn struct{ r *recorder }

func (c *recConn) Prepare(q string) (driver.Stmt, error) {
	c.r.queries = append(c.r.queries, q)
	return recStmt{c.r}, nil
}
func (c *recConn) Close() error                             { return nil }
func (c *recConn) Begin() (driver.Tx, error)                { return recTx{}, nil }
func (c *recConn) CheckNamedValue(*driver.NamedValue) error { return nil }

type recStmt struct{ r *recorder }

func (recStmt) Close() error  { return nil }
func (recStmt) NumInput() int { return -1 }
func (s recStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.r.args = len(args)
	return driver.RowsAffected(1), nil
}

// Query answers MySQL's information_schema column check with "exists".
func (recStmt) Query([]driver.Value) (driver.Rows, error) { return &oneRow{}, nil }

type recTx struct{}

func (recTx) Commit() error   { return nil }
func (recTx) Rollback() error { return nil }

type oneRow struct{ done bool }

func (*oneRow) Columns() []string { return []string{"count"} }
func (*oneRow) Close() error      { return nil }
func (o *oneRow) Next(dest []driver.Value) error {
	if o.done {
		return io.EOF
	}
	o.done = true
	dest[0] = int64(1)
	return nil
}

// columnFor maps a Result JSON key to its column where the names differ.
var columnFor = map[string]string{"time": "response_time"}

var insertColumns = regexp.MustCompile(`(?s)INSERT INTO \S+ \((.*?)\) VALUES`)

// Every Result field in the JSON output must be stored by the SQL writers.
// New fields were silently dropped from the database before (#2487).
func TestSQLWritersStoreEveryResultField(t *testing.T) {
	var want []string
	rt := reflect.TypeOf(runner.Result{})
	for i := 0; i < rt.NumField(); i++ {
		key := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
		if key == "" || key == "-" {
			continue
		}
		if col, ok := columnFor[key]; ok {
			key = col
		}
		want = append(want, key)
	}

	writers := map[string]func(*Config, *sql.DB) Database{
		"postgres": func(c *Config, db *sql.DB) Database { return &postgresDatabase{cfg: c, db: db} },
		"mysql":    func(c *Config, db *sql.DB) Database { return &mysqlDatabase{cfg: c, db: db} },
	}
	for name, newWriter := range writers {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{}
			db := sql.OpenDB(rec)
			t.Cleanup(func() { _ = db.Close() })
			w := newWriter(&Config{TableName: "results"}, db)
			ctx := context.Background()
			require.NoError(t, w.EnsureSchema(ctx))
			schema := strings.Join(rec.queries, "\n")
			require.NoError(t, w.InsertBatch(ctx, []runner.Result{{}}))

			m := insertColumns.FindStringSubmatch(rec.queries[len(rec.queries)-1])
			require.NotNil(t, m, "insert statement not found")
			var got []string
			for _, col := range strings.Split(m[1], ",") {
				got = append(got, strings.Trim(strings.TrimSpace(col), "`"))
			}
			require.Equal(t, len(got), rec.args, "insert columns and values differ")
			for _, col := range want {
				require.Contains(t, got, col, "column missing from insert")
				require.Regexp(t, `(?m)^\s*`+"`?"+col+"`?"+`\s+\w`, schema, "column missing from schema")
			}
		})
	}
}
