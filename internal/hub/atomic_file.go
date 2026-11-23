package hub

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func writeFileAtomic(target string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(target)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// ValidateNodeID enforces safe, unambiguous node identifiers (1..64 chars of [a-zA-Z0-9_-], starting with alphanumeric).
// Dots are rejected so sfn_<nodeID>.<secret> token parsing stays unambiguous, and leading '-' prevents SSH option injection.
func ValidateNodeID(id string) error {
	if len(id) == 0 {
		return errors.New("node_id cannot be empty")
	}
	if len(id) > 64 {
		return errors.New("node_id exceeds 64 characters")
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 {
			if !isAlphaNum {
				return fmt.Errorf("invalid node_id %q: must start with an alphanumeric character", id)
			}
			continue
		}
		if !isAlphaNum && c != '-' && c != '_' {
			return fmt.Errorf("invalid node_id %q: only letters, digits, '-' and '_' are allowed", id)
		}
	}
	return nil
}
