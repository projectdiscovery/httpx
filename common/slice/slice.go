package slice

// IntSliceContains check if a slice contains the specified int value
func IntSliceContains(sl []int, v int) bool {
	for _, vv := range sl {
		if vv == v {
			return true
		}
	}
	return false
}

// UIntSliceContains check if a slice contains the specified uint value
func UInt32SliceContains(sl []uint32, v uint32) bool {
	for _, vv := range sl {
		if vv == v {
			return true
		}
	}
	return false
}

// StringSliceContains check if a slice contains the specified int value
func StringSliceContains(sl []string, v string) bool {
	for _, vv := range sl {
		if vv == v {
			return true
		}
	}
	return false
}

// ToSlice creates a slice with all string keys from a map
func ToSlice(m map[string]struct{}) (s []string) {
	for k := range m {
		s = append(s, k)
	}

	return
}
