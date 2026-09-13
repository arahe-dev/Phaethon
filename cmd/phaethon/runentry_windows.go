//go:build windows

package main

import "golang.org/x/sys/windows/registry"

// removeRunValue deletes a value from the current user's Run key.
//
// It exists so an uninstall cannot leave an entry that starts a daemon whose
// binary has been removed.
func removeRunValue(name string) bool {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	if err := key.DeleteValue(name); err != nil {
		return false
	}
	return true
}
