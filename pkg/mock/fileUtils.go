// +build !release

package mock

import (
	"fmt"
	"github.com/bmatcuk/doublestar"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var dirContent []byte

// FilesMock implements the functions from piperutils.Files with an in-memory file system.
type FilesMock struct {
	Files        map[string]*[]byte
	RemovedFiles map[string]*[]byte
}

func (f *FilesMock) init() {
	if f.Files == nil {
		f.Files = map[string]*[]byte{}
	}
	if f.RemovedFiles == nil {
		f.RemovedFiles = map[string]*[]byte{}
	}
}

// AddFile establishes the existence of a virtual file.
func (f *FilesMock) AddFile(path string, contents []byte) {
	f.init()
	f.Files[path] = &contents
}

// AddDir establishes the existence of a virtual directory.
func (f *FilesMock) AddDir(path string) {
	f.init()
	f.Files[path] = &dirContent
}

// FileExists returns true if file content has been associated with the given path, false otherwise.
func (f *FilesMock) FileExists(path string) (bool, error) {
	if f.Files == nil {
		return false, nil
	}
	content, exists := f.Files[path]
	if !exists {
		return false, fmt.Errorf("'%s': %w", path, os.ErrNotExist)
	}
	return content != &dirContent, nil
}

// DirExists returns true, if the given path is a previously added directory, or a parent directory for any of the
// previously added files.
func (f *FilesMock) DirExists(path string) (bool, error) {
	for entry, content := range f.Files {
		var dirComponents []string
		if content == &dirContent {
			dirComponents = strings.Split(entry, string(os.PathSeparator))
		} else {
			dirComponents = strings.Split(filepath.Dir(entry), string(os.PathSeparator))
		}
		if len(dirComponents) > 0 {
			dir := ""
			for i, component := range dirComponents {
				if i == 0 {
					dir = component
				} else {
					dir = dir + string(os.PathSeparator) + component
				}
				if dir == path {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// Copy checks if content has been associated with the given src path, and if so copies it under the given path dst.
func (f *FilesMock) Copy(src, dst string) (int64, error) {
	f.init()
	content, exists := f.Files[src]
	if !exists || content == &dirContent {
		return 0, fmt.Errorf("cannot copy '%s': %w", src, os.ErrNotExist)
	}
	f.AddFile(dst, *content)
	return int64(len(*content)), nil
}

// FileRead returns the content previously associated with the given path via AddFile(), or an error if no
// content has been associated.
func (f *FilesMock) FileRead(path string) ([]byte, error) {
	f.init()
	content, exists := f.Files[path]
	if !exists {
		return nil, fmt.Errorf("could not read '%s'", path)
	}
	// check if trying to open a directory for reading
	if content == &dirContent {
		return nil, fmt.Errorf("could not read '%s': %w", path, os.ErrInvalid)
	}
	return *content, nil
}

// FileWrite just forwards to AddFile(), i.e. the content is associated with the given path.
func (f *FilesMock) FileWrite(path string, content []byte, _ os.FileMode) error {
	// NOTE: FilesMock could be extended to have a set of paths for which FileWrite should fail.
	// This is why AddFile() exists separately, to differentiate the notion of setting up the mocking
	// versus implementing the methods from Files.
	f.AddFile(path, content)
	return nil
}

// FileRemove deletes the association of the given path with any content and records the removal of the file.
// If the path has not been registered before, it returns an error.
func (f *FilesMock) FileRemove(path string) error {
	if f.Files == nil {
		return fmt.Errorf("the file '%s' does not exist: %w", path, os.ErrNotExist)
	}
	content, exists := f.Files[path]
	if !exists {
		return fmt.Errorf("the file '%s' does not exist: %w", path, os.ErrNotExist)
	}
	delete(f.Files, path)
	f.RemovedFiles[path] = content
	return nil
}

// MkdirAll creates a directory in the in-memory file system, so that this path is established to exist.
func (f *FilesMock) MkdirAll(path string, _ os.FileMode) error {
	// NOTE: FilesMock could be extended to have a set of paths for which MkdirAll should fail.
	// This is why AddDir() exists separately, to differentiate the notion of setting up the mocking
	// versus implementing the methods from Files.
	f.AddDir(path)
	return nil
}

// Glob returns an array of path strings which match the given glob-pattern. Double star matching is supported.
func (f *FilesMock) Glob(pattern string) ([]string, error) {
	var matches []string
	if f.Files == nil {
		return matches, nil
	}
	for path := range f.Files {
		matched, _ := doublestar.Match(pattern, path)
		if matched {
			matches = append(matches, path)
		}
	}
	// The order in f.Files is not deterministic, this would result in flaky tests.
	sort.Strings(matches)
	return matches, nil
}
