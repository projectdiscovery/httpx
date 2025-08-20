package runner

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/pkg/errors"
)

type JSONExporter struct {
	options *JSONExportOptions
	mutex   *sync.Mutex
	rows    []Result
}

type JSONExportOptions struct {
	File string `yaml:"file"`
}

// NewJSONExporter creates a new JSON exporter
func NewJSONExporter(options *JSONExportOptions) (*JSONExporter, error) {

	exporter := &JSONExporter{
		mutex:   &sync.Mutex{},
		options: options,
		rows:    []Result{},
	}
	return exporter, nil
}

// Export adds result and writes batch when full
func (exporter *JSONExporter) Export(result *Result) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	exporter.rows = append(exporter.rows, *result)

	return nil
}

// Close writes remaining data and closes
func (exporter *JSONExporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// Convert the rows to JSON byte array
	obj, err := json.Marshal(exporter.rows)
	if err != nil {
		return errors.Wrap(err, "failed to generate JSON report")
	}

	// Attempt to write the JSON to file specified in options.JSONExport
	if err := os.WriteFile(exporter.options.File, obj, 0644); err != nil {
		return errors.Wrap(err, "failed to create JSON file")
	}

	return nil
}
