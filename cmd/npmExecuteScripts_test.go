package cmd

import (
	"github.com/SAP/jenkins-library/pkg/mock"
	"github.com/SAP/jenkins-library/pkg/npm"
	"github.com/bmatcuk/doublestar"
	"github.com/stretchr/testify/assert"
	"sort"
	"testing"
)

type npmExecuteScriptsMockUtilsBundle struct {
	execRunner mock.ExecMockRunner
	files      map[string]string
}

func (u *npmExecuteScriptsMockUtilsBundle) FileExists(path string) (bool, error) {
	_, exists := u.files[path]
	return exists, nil
}

func (u *npmExecuteScriptsMockUtilsBundle) FileRead(path string) ([]byte, error) {
	return []byte(u.files[path]), nil
}

// duplicated from nexusUpload_test.go for now, refactor later?
func (u *npmExecuteScriptsMockUtilsBundle) Glob(pattern string) ([]string, error) {
	var matches []string
	for path := range u.files {
		matched, _ := doublestar.Match(pattern, path)
		if matched {
			matches = append(matches, path)
		}
	}
	// The order in m.files is not deterministic, this would result in flaky tests.
	sort.Sort(byLen(matches))
	return matches, nil
}

func (u *npmExecuteScriptsMockUtilsBundle) Getwd() (dir string, err error) {
	return "/project", nil
}

func (u *npmExecuteScriptsMockUtilsBundle) Chdir(dir string) error {
	return nil
}

func (u *npmExecuteScriptsMockUtilsBundle) GetExecRunner() npm.ExecRunner {
	return &u.execRunner
}

func TestNpmExecuteScripts(t *testing.T) {
	t.Run("Call without install and run-scripts", func(t *testing.T) {
		utils := newNpmExecuteScriptsMockUtilsBundle()
		utils.files["package.json"] = "{\"name\": \"Test\" }"
		utils.files["package-lock.json"] = "{\"name\": \"Test\" }"
		config := npmExecuteScriptsOptions{}

		err := runNpmExecuteScripts(&utils, &config)

		assert.NoError(t, err)
		assert.Equal(t, 0, len(utils.execRunner.Calls))
	})

	t.Run("Project with package lock", func(t *testing.T) {
		utils := newNpmExecuteScriptsMockUtilsBundle()
		utils.files["package.json"] = "{\"scripts\": { \"foo\": \"\" , \"bar\": \"\" } }"
		utils.files["foo/bar/node_modules/package.json"] = "{\"name\": \"Test\" }" // is filtered out
		utils.files["gen/bar/package.json"] = "{\"name\": \"Test\" }"              // is filtered out
		utils.files["foo/gen/package.json"] = "{\"name\": \"Test\" }"              // is filtered out
		utils.files["package-lock.json"] = "{\"name\": \"Test\" }"
		options := npmExecuteScriptsOptions{}
		options.Install = true
		options.RunScripts = []string{"foo", "bar"}
		options.DefaultNpmRegistry = "foo.bar"

		err := runNpmExecuteScripts(&utils, &options)

		assert.NoError(t, err)
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"ci"}}, utils.execRunner.Calls[2])
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"run", "foo"}}, utils.execRunner.Calls[3])
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"run", "bar"}}, utils.execRunner.Calls[4])
		assert.Equal(t, 5, len(utils.execRunner.Calls))
	})

	t.Run("Project with two package json files", func(t *testing.T) {
		utils := newNpmExecuteScriptsMockUtilsBundle()
		utils.files["package.json"] = "{\"scripts\": { \"foo\": \"\" , \"bar\": \"\" } }"
		utils.files["foo/bar/package.json"] = "{\"scripts\": { \"foo\": \"\" , \"bar\": \"\" } }"
		utils.files["package-lock.json"] = "{\"name\": \"Test\" }"
		options := npmExecuteScriptsOptions{}
		options.Install = true
		options.RunScripts = []string{"foo", "bar"}

		err := runNpmExecuteScripts(&utils, &options)

		assert.NoError(t, err)
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"ci"}}, utils.execRunner.Calls[2])
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"ci"}}, utils.execRunner.Calls[5])
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"run", "foo"}}, utils.execRunner.Calls[6])
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"run", "foo"}}, utils.execRunner.Calls[7])
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"run", "bar"}}, utils.execRunner.Calls[8])
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"run", "bar"}}, utils.execRunner.Calls[9])
		assert.Equal(t, 10, len(utils.execRunner.Calls))
	})

	t.Run("Project with yarn lock", func(t *testing.T) {
		utils := newNpmExecuteScriptsMockUtilsBundle()
		utils.files["package.json"] = "{\"scripts\": { \"foo\": \"\" , \"bar\": \"\" } }"
		utils.files["yarn.lock"] = "{\"name\": \"Test\" }"
		options := npmExecuteScriptsOptions{}
		options.Install = true
		options.RunScripts = []string{"foo", "bar"}

		err := runNpmExecuteScripts(&utils, &options)

		assert.NoError(t, err)
		assert.Equal(t, mock.ExecCall{Exec: "yarn", Params: []string{"install", "--frozen-lockfile"}}, utils.execRunner.Calls[2])
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"run", "foo"}}, utils.execRunner.Calls[3])
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"run", "bar"}}, utils.execRunner.Calls[4])
	})

	t.Run("Project without lock file", func(t *testing.T) {
		utils := newNpmExecuteScriptsMockUtilsBundle()
		utils.files["package.json"] = "{\"scripts\": { \"foo\": \"\" , \"bar\": \"\" } }"
		options := npmExecuteScriptsOptions{}
		options.Install = true
		options.RunScripts = []string{"foo", "bar"}

		err := runNpmExecuteScripts(&utils, &options)

		assert.NoError(t, err)
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"install"}}, utils.execRunner.Calls[2])
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"run", "foo"}}, utils.execRunner.Calls[3])
		assert.Equal(t, mock.ExecCall{Exec: "npm", Params: []string{"run", "bar"}}, utils.execRunner.Calls[4])
	})
}

func newNpmExecuteScriptsMockUtilsBundle() npmExecuteScriptsMockUtilsBundle {
	utils := npmExecuteScriptsMockUtilsBundle{}
	utils.files = map[string]string{}
	return utils
}
