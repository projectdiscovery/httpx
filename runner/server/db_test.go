package server

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetGet(t *testing.T) {
	db, err := NewHttpxDB("")
	if err != nil {
		t.Fatalf("could not create db: %v", err)
	}
	defer db.Close()

	value := []byte("test value")
	err = db.Set(value)
	if err != nil {
		t.Fatalf("could not set value: %v", err)
	}

	ret, err := db.Get("1001")
	if err != nil {
		t.Fatalf("could not get value: %v", err)
	}

	assert.Equal(t, value, ret)
}

func TestGetWithCursor(t *testing.T) {
	db, err := NewHttpxDB("")
	if err != nil {
		t.Fatalf("could not create db: %v", err)
	}
	defer db.Close()

	// Insert some test data
	for i := 0; i < 10; i++ {
		value := []byte(fmt.Sprintf("value-%d", i))
		err = db.Set(value)
		if err != nil {
			t.Fatalf("could not set value: %v", err)
		}
	}

	// Test pagination
	buff, _, err := db.GetWithCursor(5, "")
	if err != nil {
		t.Fatalf("could not get page: %v", err)
	}

	var result []string
	for {
		line, err := buff.ReadString('\n')
		if err != nil {
			break
		}
		result = append(result, line[:len(line)-1]) // trim newline
	}

	expected := []string{"value-0", "value-1", "value-2", "value-3", "value-4"}
	assert.Equal(t, expected, result)

	// Get next page
	buff, lastKey, err := db.GetWithCursor(5, "1005")
	if err != nil {
		t.Fatalf("could not get page: %v", err)
	}

	result = make([]string, 0)
	for {
		line, err := buff.ReadString('\n')
		if err != nil {
			break
		}
		result = append(result, line[:len(line)-1]) // trim newline
	}

	expected = []string{"value-5", "value-6", "value-7", "value-8", "value-9"}
	assert.Equal(t, expected, result)
	assert.Equal(t, "1010", lastKey)
}
