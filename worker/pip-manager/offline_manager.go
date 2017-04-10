package pip

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	docker "github.com/fsouza/go-dockerclient"

	"github.com/open-lambda/open-lambda/worker/dockerutil"
)

/*
 * OfflineInstallManager is the interface for installing unpack-only pip packages.
 */

type OfflineInstallManager interface {
	Prepare(pkgs []string) ([]string, error)
	Unpack(handler string, pkgs []string) ([]string, error)
}

// Package identifies a package with its name and an exact version.
type Package struct {
	Name    string
	Version string
}

func (p Package) String() string {
	return fmt.Sprintf("%s,%s", p.Name, p.Version)
}

type OfflineInstaller struct {
	client       *docker.Client
	script       string
	pipMirror    string
	unpackMirror string
	depGraph     map[Package][]Package // package -> dependencies
}

func NewOfflineInstaller(pipMirror string, unpackMirror string) (*OfflineInstaller, error) {
	var client *docker.Client
	if c, err := docker.NewClientFromEnv(); err != nil {
		return nil, err
	} else {
		client = c
	}

	if pipMirror == "" {
		pipMirror = "https://pypi.python.org/simple"
	}
	absUnpackMirror, err := filepath.Abs(unpackMirror)
	if err != nil {
		return nil, err
	}

	// TODO: better way to find the script
	script := filepath.Join(filepath.Dir(os.Args[0]), "..", "worker", "pip-manager", "scripts", "pip_patched.py")
	script, _ = filepath.Abs(script)

	if err := os.MkdirAll(absUnpackMirror, os.ModeDir); err != nil {
		return nil, err
	}

	// Read dependencies from file if exists
	depsFile := filepath.Join(absUnpackMirror, "deps.txt")
	depGraph := map[Package][]Package{}
	if _, err := os.Stat(depsFile); err != nil && !os.IsNotExist(err) {
		return nil, err
	} else if err == nil {
		if file, err := os.Open(depsFile); err != nil {
			return nil, err
		} else {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				pkgs := []Package{}
				for _, pkgtext := range strings.Split(scanner.Text(), " ") {
					parts := strings.Split(pkgtext, ",")
					pkgs = append(pkgs, Package{
						Name:    parts[0],
						Version: parts[1],
					})
				}
				depGraph[pkgs[0]] = pkgs[1:]
			}
		}
	}

	manager := &OfflineInstaller{
		client:       client,
		script:       script,
		pipMirror:    pipMirror,
		unpackMirror: absUnpackMirror,
		depGraph:     depGraph,
	}

	return manager, nil
}

// installDir gets the installation directory of a package in the unpack mirror.
func (o *OfflineInstaller) installDir(pkg Package) string {
	pkgstr := pkg.String()
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(pkgstr)))
	return filepath.Join(o.unpackMirror, "packages", hash[:2], hash[2:4], hash[4:], pkgstr)
}

// getAllDeps gets the recursive dependencies of pkg and stores the result in allDeps.
func (o *OfflineInstaller) getAllDeps(pkg Package, allDeps map[Package]bool) error {
	if _, ok := allDeps[pkg]; ok {
		return nil
	}
	if deps, ok := o.depGraph[pkg]; !ok {
		return fmt.Errorf("package %v has not been installed\n", pkg)
	} else if deps == nil {
		return fmt.Errorf("package %v cannot be installed\n", pkg)
	} else {
		allDeps[pkg] = true
		for _, dep := range deps {
			if err := o.getAllDeps(dep, allDeps); err != nil {
				// should not get here
				return fmt.Errorf("from %s: %v", pkg.String(), err)
			}
		}
		return nil
	}
}

// GetAllDeps gets the recursive dependencies of pkg.
func (o *OfflineInstaller) GetAllDeps(pkg Package) (map[Package]bool, error) {
	allDeps := map[Package]bool{}
	if err := o.getAllDeps(pkg, allDeps); err != nil {
		return nil, err
	}
	return allDeps, nil
}

// Resolve resolves the exact version given a package specification.
func (o *OfflineInstaller) Resolve(specs []string) ([]Package, error) {
	cmd := exec.Command("python", append([]string{
		o.script, "resolve", "-qqq", "-i", o.pipMirror,
	}, specs...)...)
	if output, err := cmd.Output(); err != nil {
		return nil, fmt.Errorf("fail to resolve packages: %s", string(err.(*exec.ExitError).Stderr))
	} else {
		resolved := []Package{}
		scanner := bufio.NewScanner(bytes.NewBuffer(output))
		for scanner.Scan() {
			parts := strings.Split(scanner.Text(), ",")
			resolved = append(resolved, Package{
				Name:    strings.ToLower(parts[0]),
				Version: parts[1],
			})
		}
		return resolved, nil
	}
}

// prepare installs a package in the unpack mirror and archives it.
func (o *OfflineInstaller) prepare(pkg Package) error {
	pkgstr := pkg.String()
	if _, ok := o.depGraph[pkg]; ok {
		return nil
	}
	// avoid circular dependencies.
	o.depGraph[pkg] = nil

	fmt.Printf("Installing package %v\n", pkg)

	installDir := o.installDir(pkg)
	if err := os.MkdirAll(installDir, os.ModeDir); err != nil {
		return fmt.Errorf("[from %v] %v", pkg, err)
	}

	// installation directory inside container.
	pkgdir := fmt.Sprintf("/pip_packages/%s", pkgstr)
	binds := []string{
		fmt.Sprintf("%s:%s", installDir, pkgdir),
	}

	spec := fmt.Sprintf("%s==%s", pkg.Name, pkg.Version)

	container, err := o.client.CreateContainer(
		docker.CreateContainerOptions{
			Config: &docker.Config{
				Image: dockerutil.INSTALLER_IMAGE,
				Cmd: []string{
					"python",
					"pip_patched.py", "install",
					"-t", pkgdir,
					"-qqq",
					"-i", o.pipMirror,
					spec,
				},
			},
			HostConfig: &docker.HostConfig{
				//AutoRemove: true,
				Binds: binds,
				// TODO: update go-dockerclient to support tmpfs
				//ReadonlyRootfs: true,
				//Tmpfs: map[string]string{"/tmp": ""},
			},
		},
	)
	if err != nil {
		os.RemoveAll(installDir)
		return fmt.Errorf("[from %v] fail to create installation container: %v", pkg, err)
	}

	// equivalent to autoremove
	defer o.client.RemoveContainer(docker.RemoveContainerOptions{ID: container.ID})

	if err = o.client.StartContainer(container.ID, nil); err != nil {
		os.RemoveAll(installDir)
		return fmt.Errorf("[from %v] fail to install package: %v", pkg, err)
	} else if exitcode, err := o.client.WaitContainer(container.ID); err != nil {
		os.RemoveAll(installDir)
		return fmt.Errorf("[from %v] error occurs when waiting for container: %v", pkg, err)
	} else if exitcode != 0 {
		os.RemoveAll(installDir)
		var buf bytes.Buffer
		err = o.client.Logs(docker.LogsOptions{
			Container:   container.ID,
			ErrorStream: &buf,
			Follow:      true,
			Stderr:      true,
		})
		if err != nil {
			return fmt.Errorf("[from %v] fail to get error logs from installation container: %v", pkg, err)
		}
		return fmt.Errorf("[from %v] container exited with non-zero code %d: {stderr start}\n%s{stderr end}", pkg, exitcode, buf.String())
	}

	var buf bytes.Buffer
	err = o.client.Logs(docker.LogsOptions{
		Container:    container.ID,
		OutputStream: &buf,
		Follow:       true,
		Stdout:       true,
	})
	if err != nil {
		os.RemoveAll(installDir)
		return fmt.Errorf("[from %v] fail to get logs from installation container: %v", pkg, err)
	}

	deps := []string{}
	scanner := bufio.NewScanner(&buf)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ",")
		name := strings.ToLower(parts[0])
		spec := parts[1]
		// TODO: handle extras
		// extras = parts[2]
		deps = append(deps, fmt.Sprintf("%s%s", name, spec))
	}

	resolved, err := o.Resolve(deps)
	if err != nil {
		os.RemoveAll(installDir)
		return fmt.Errorf("[from %v] error during resolving dependency versions: %v", pkg, err)
	}

	for idx, p := range resolved {
		if p.Version == "" {
			os.RemoveAll(installDir)
			return fmt.Errorf("[from %v] cannot resolve dependency: %s", pkg, deps[idx])
		} else if err := o.prepare(p); err != nil {
			os.RemoveAll(installDir)
			return fmt.Errorf("[from %v] %v", pkg, err)
		}
	}

	// compress files with sources removed
	cmd := exec.Command("tar", "--remove-files", "-zcf", fmt.Sprintf("%s.tar.gz", installDir), "-C", installDir, ".")
	if err := cmd.Run(); err != nil {
		var msg string
		if exitErr, ok := err.(*exec.ExitError); ok {
			msg = string(exitErr.Stderr)
		} else {
			msg = err.Error()
		}
		os.RemoveAll(installDir)
		return fmt.Errorf("[from %v] error when creating package archive: %s", pkg, msg)
	}

	o.depGraph[pkg] = resolved
	return nil
}

// Prepare installs a list of package specifications and returns a list of
// remaining ones.
func (o *OfflineInstaller) Prepare(pkgs []string) ([]string, error) {
	remains := []string{}

	resolved, err := o.Resolve(pkgs)
	if err != nil {
		return nil, err
	}

	for idx, pkg := range resolved {
		fmt.Printf("(%d/%d) Preparing package %v\n", idx+1, len(resolved), pkg)
		if pkg.Version == "" {
			fmt.Printf("%s: version resolution fails\n", pkgs[idx])
			remains = append(remains, pkgs[idx])
		} else if err := o.prepare(pkg); err != nil {
			fmt.Printf("%s: installation fails: %s\n", pkgs[idx], err.Error())
			remains = append(remains, pkgs[idx])
		}
	}

	// write dependencies to file
	depsText := ""
	for pkg, deps := range o.depGraph {
		if deps == nil {
			continue
		}
		depsText += pkg.String()
		for _, dep := range deps {
			depsText += " " + dep.String()
		}
		depsText += "\n"
	}

	depsFile := filepath.Join(o.unpackMirror, "deps.txt")
	if err := ioutil.WriteFile(depsFile, []byte(depsText), 0644); err != nil {
		return nil, err
	}

	return remains, nil
}

// TODO: eviction
// Unpack decompresses a list of archived installed packages to a target directory.
func (o *OfflineInstaller) Unpack(targetDir string, pkgs []string) ([]string, error) {
	allDeps := map[Package]bool{}
	toInstall := []string{}

	if resolved, err := o.Resolve(pkgs); err != nil {
		return nil, err
	} else {
		for idx, pkg := range resolved {
			if pkg.Version == "" {
				fmt.Printf("specification cannot be resolved: %s\n", pkgs[idx])
				toInstall = append(toInstall, pkgs[idx])
			} else if deps, err := o.GetAllDeps(resolved[0]); err != nil {
				fmt.Printf("some dependencies cannot be installed: %v\n", err)
				toInstall = append(toInstall, pkgs[idx])
			} else {
				for dep := range deps {
					allDeps[dep] = true
				}
			}
		}
	}

	// TODO: better way to pick one version for a package
	// for now, an arbitrary version is picked
	oneVersion := map[string]Package{}
	for pkg, _ := range allDeps {
		oneVersion[pkg.Name] = pkg
	}

	for _, pkg := range oneVersion {
		archive := o.installDir(pkg) + ".tar.gz"

		cmd := exec.Command("tar", "-xf", archive, "-C", targetDir)
		if err := cmd.Run(); err != nil {
			var msg string
			if exitErr, ok := err.(*exec.ExitError); ok {
				msg = string(exitErr.Stderr)
			} else {
				msg = err.Error()
			}
			return nil, fmt.Errorf("error when extracting package archive: %s", msg)
		}
	}
	return toInstall, nil
}
