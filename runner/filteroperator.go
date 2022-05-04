package runner

import (
	"fmt"
	"strconv"
	"strings"
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
func (f FilterOperator) Parse(flagValue string) (string, float64, error) {
	var (
		operator string
		value    float64
		err      error
	)
	for _, op := range compareOperators {
		if strings.Contains(flagValue, op) {
			spl := strings.SplitAfter(flagValue, op)
			operator = strings.Trim(spl[0], " ")
			value, err = strconv.ParseFloat(strings.Trim(spl[1], " "), 64)
			if err != nil {
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
