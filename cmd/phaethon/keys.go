package main

import "sort"

// sortedKeys returns the keys of a string-keyed map in ascending order, so
// CLI output is stable between runs.
func sortedStringKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedIntKeys is the int64-map convenience the status command uses.
func sortedIntKeys(m map[string]int64) []string { return sortedStringKeys(m) }
