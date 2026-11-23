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
				// A bare number is read as seconds. This retry used to drop its
				// error, so a number too large to hold as a duration left value
				// at zero and reported nothing, and the filter then matched
				// every host instead of rejecting the flag.
				value, err = time.ParseDuration(fmt.Sprintf("%ss", timeVal))
				if err != nil {
					return operator, value, fmt.Errorf("invalid value provided for %s", f.flag)
				}
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
