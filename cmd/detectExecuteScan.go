package cmd

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	//sliceUtils "github.com/SAP/jenkins-library/pkg/piperutils"

	"github.com/SAP/jenkins-library/pkg/command"
	piperhttp "github.com/SAP/jenkins-library/pkg/http"
	"github.com/SAP/jenkins-library/pkg/log"
	"github.com/SAP/jenkins-library/pkg/maven"
	"github.com/SAP/jenkins-library/pkg/piperutils"
	"github.com/SAP/jenkins-library/pkg/telemetry"
	"github.com/SAP/jenkins-library/pkg/versioning"
)

const classpathFileNameDetectExecute = "detect-execute-scan-cp.txt"

type buildExecRunner interface {
	Stdout(out io.Writer)
	Stderr(err io.Writer)
	SetDir(d string)
	RunExecutable(e string, p ...string) error
}

type utilsBundleDetectMaven struct {
	*piperhttp.Client
	*piperutils.Files
}

func newUtils() *utilsBundleDetectMaven {
	return &utilsBundleDetectMaven{
		Client: &piperhttp.Client{},
		Files:  &piperutils.Files{},
	}
}

func detectExecuteScan(config detectExecuteScanOptions, telemetryData *telemetry.CustomData) {
	c := command.Command{}
	e := command.Command{}
	// reroute command output to logging framework
	c.Stdout(log.Writer())
	c.Stderr(log.Writer())
	runDetect(config, &c, &e)
}

func runDetect(config detectExecuteScanOptions, command command.ShellRunner, e command.ExecRunner) {
	// detect execution details, see https://synopsys.atlassian.net/wiki/spaces/INTDOCS/pages/88440888/Sample+Synopsys+Detect+Scan+Configuration+Scenarios+for+Black+Duck

	if config.BuildTool == "maven" {
		installMavenArtifactsForDetectExecute(e, config)
		mavenDependencyResolve(config, e)
		//buildArtifacts(config, classpathFileNameDetectExecute, mavenCommand)
		//if err != nil {
		//	return err
		//}
	} else {
		log.Entry().Info("No maven build ,continuing without build, found BuildTool :", config.BuildTool)
	}
	args := []string{"bash <(curl -s https://detect.synopsys.com/detect.sh)"}
	args = addDetectArgs(args, config)
	script := strings.Join(args, " ")

	command.SetDir(".")
	command.SetEnv([]string{"BLACKDUCK_SKIP_PHONE_HOME=true"})

	err := command.RunShell("/bin/bash", script)
	if err != nil {
		log.Entry().
			WithError(err).
			Fatal("failed to execute detect scan")
	}
}

func installMavenArtifactsForDetectExecute(e command.ExecRunner, config detectExecuteScanOptions) error {
	pomXMLExists, err := piperutils.FileExists("pom.xml")
	if err != nil {
		return err
	}
	if pomXMLExists {
		err = maven.InstallMavenArtifacts(e, maven.EvaluateOptions{M2Path: config.M2Path})
		if err != nil {
			return err
		}
	}
	return nil
}

func mavenDependencyResolve(config detectExecuteScanOptions, e command.ExecRunner) {
	pomFiles, err := newUtils().Glob(filepath.Join("**", "pom.xml"))
	if err != nil {
		log.Entry().WithError(err).Warn("no pom xml found")
	}

	if config.M2Path != "" {
		config.M2Path, err = filepath.Abs(config.M2Path)
		if err != nil {
			log.Entry().WithError(err).Warn("absolute file path error for pom")
		}
	}

	for _, pomFile := range pomFiles {
		log.Entry().Info("Installing maven dependencies from pom: " + pomFile)
		executeOptions := maven.ExecuteOptions{
			PomPath:             pomFile,
			ProjectSettingsFile: config.ProjectSettingsFile,
			GlobalSettingsFile:  config.GlobalSettingsFile,
			M2Path:              config.M2Path,
			Goals:               []string{"dependency:resolve"},
			//Defines:             []string{fmt.Sprintf("-Dmdep.outputFile=%v", file), "-DincludeScope=compile"},
			ReturnStdout: true,
		}
		_, err := maven.Execute(&executeOptions, e)
		if err != nil {
			log.Entry().WithError(err).Warn("failed to download dependency for: ", pomFile)
		}
	}
}

/* func buildArtifacts(config detectExecuteScanOptions, file string, mavenCommand buildExecRunner) {
	if config.BuildTool == "maven" {
		executeOptions := maven.ExecuteOptions{
			PomPath:             config.BuildDescriptorFile,
			ProjectSettingsFile: config.ProjectSettingsFile,
			GlobalSettingsFile:  config.GlobalSettingsFile,
			M2Path:              config.M2Path,
			Goals:               []string{"install"},
			//Defines:             []string{fmt.Sprintf("-Dmdep.outputFile=%v", file), "-DincludeScope=compile"},
			ReturnStdout:        true,
		}
		_, err := maven.Execute(&executeOptions, mavenCommand)
		if err != nil {
			log.Entry().WithError(err).Warn("failed to determine classpath using Maven")
		}
	}
} */

func addDetectArgs(args []string, config detectExecuteScanOptions) []string {

	coordinates := struct {
		Version string
	}{
		Version: config.Version,
	}

	_, detectVersionName := versioning.DetermineProjectCoordinates("", config.VersioningModel, coordinates)

	args = append(args, config.ScanProperties...)

	args = append(args, fmt.Sprintf("--blackduck.url=%v", config.ServerURL))
	args = append(args, fmt.Sprintf("--blackduck.api.token=%v", config.APIToken))
	// ProjectNames, VersionName, GroupName etc can contain spaces and need to be escaped using double quotes in CLI
	// Hence the string need to be surrounded by \"
	args = append(args, fmt.Sprintf("--detect.project.name=\\\"%v\\\"", config.ProjectName))
	args = append(args, fmt.Sprintf("--detect.project.version.name=\\\"%v\\\"", detectVersionName))

	// Groups parameter is added only when there is atleast one non-empty groupname provided
	if len(config.Groups) > 0 && len(config.Groups[0]) > 0 {
		args = append(args, fmt.Sprintf("--detect.project.user.groups=\\\"%v\\\"", strings.Join(config.Groups, "\\\",\\\"")))
	}

	// Atleast 1, non-empty category to fail on must be provided
	if len(config.FailOn) > 0 && len(config.FailOn[0]) > 0 {
		args = append(args, fmt.Sprintf("--detect.policy.check.fail.on.severities=%v", strings.Join(config.FailOn, ",")))
	}

	codeLocation := config.CodeLocation
	if len(codeLocation) == 0 && len(config.ProjectName) > 0 {
		codeLocation = fmt.Sprintf("%v/%v", config.ProjectName, detectVersionName)
	}
	args = append(args, fmt.Sprintf("--detect.code.location.name=\\\"%v\\\"", codeLocation))

	if piperutils.ContainsString(config.Scanners, "signature") {
		args = append(args, fmt.Sprintf("--detect.blackduck.signature.scanner.paths=%v", strings.Join(config.ScanPaths, ",")))
	}

	if piperutils.ContainsString(config.Scanners, "source") {
		args = append(args, fmt.Sprintf("--detect.source.path=%v", config.ScanPaths[0]))
	}
	return args
}
