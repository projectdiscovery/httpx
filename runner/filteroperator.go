package runner

import (
	"fmt"
	"strings"
	"time"
)

var (
	greaterThan      = ">"
	lessThan         = "<"
	equal            = "="
	greaterThanEq    = ">="
	lessThanEq       = "<="
	notEq            = "!="
	compareOperators = []string{greaterThanEq, lessThanEq, equal, lessThan, greaterThan, notEq}
)

type FilterOperator struct {
	flag string
}

// Parse the given value into operator and value pair
func (f FilterOperator) Parse(flagValue string) (string, time.Duration, error) {
	var (
		operator string
		value    time.Duration
		err      error
	)
	for _, op := range compareOperators {
		if strings.Contains(flagValue, op) {
			splittedFlagValue := strings.SplitAfter(flagValue, op)
			operator = strings.Trim(splittedFlagValue[0], " ")
			timeVal := strings.Trim(splittedFlagValue[1], " ")
			value, err = time.ParseDuration(timeVal)
			if err != nil && strings.Contains(err.Error(), "missing unit") {
				value, _ = time.ParseDuration(fmt.Sprintf("%ss", timeVal))
			} else if err != nil {
				return operator, value, fmt.Errorf("invalid value provided for %s", f.flag)
			}
			break
		}
	}
	if operator == "" {
		return operator, value, fmt.Errorf("invalid operator provided for %s, valid operators are %s", f.flag, strings.Join(compareOperators, ","))
	}
	return operator, value, nil
}
