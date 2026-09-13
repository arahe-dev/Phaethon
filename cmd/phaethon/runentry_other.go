//go:build !windows

package main

// removeRunValue is only meaningful where a Run key exists.
func removeRunValue(string) bool { return false }
