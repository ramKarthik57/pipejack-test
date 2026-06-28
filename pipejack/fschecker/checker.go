package fschecker

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type FileChange struct {
	Path string
	Type string // "added", "modified", "deleted"
}

type MerkleNode struct {
	Hash     string
	Children map[string]*MerkleNode
}

// BuildMerkleTree walks the directory and returns the root node and a flat map of file hashes.
func BuildMerkleTree(root string, ignorePrefixes []string) (*MerkleNode, map[string]string, error) {
	fileHashes := make(map[string]string)
	rootNode := &MerkleNode{Children: make(map[string]*MerkleNode)}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, _ := filepath.Rel(root, path)
		for _, prefix := range ignorePrefixes {
			if strings.HasPrefix(relPath, prefix) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil
		}
		hash := hex.EncodeToString(h.Sum(nil))
		fileHashes[relPath] = hash
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	var sorted []string
	for p := range fileHashes {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	concat := ""
	for _, p := range sorted {
		concat += p + ":" + fileHashes[p] + "\n"
	}
	rootHash := sha256.Sum256([]byte(concat))
	rootNode.Hash = hex.EncodeToString(rootHash[:])
	return rootNode, fileHashes, nil
}

// CompareSnapshots returns the list of differences between two file hash maps.
func CompareSnapshots(pre, post map[string]string) []FileChange {
	var changes []FileChange
	for path, preHash := range pre {
		postHash, exists := post[path]
		if !exists {
			changes = append(changes, FileChange{Path: path, Type: "deleted"})
		} else if preHash != postHash {
			changes = append(changes, FileChange{Path: path, Type: "modified"})
		}
	}
	for path := range post {
		if _, exists := pre[path]; !exists {
			changes = append(changes, FileChange{Path: path, Type: "added"})
		}
	}
	return changes
}
