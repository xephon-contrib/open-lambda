package pip

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	docker "github.com/fsouza/go-dockerclient"

	"github.com/open-lambda/open-lambda/worker/dockerutil"
)

type UnpackMirrorClient struct {
	BasicPipManager
	unpackMirror string
}

func (c *UnpackMirrorClient) Unpack(targetDir string, pkgs []Package) (remains []Package, err error) {
	return nil, nil
}

/*
 * OfflineInstallManager is the interface for installing unpack-only pip packages.
 */

type UnpackMirrorManager interface {
	Prepare(pkgs []string) ([]string, error)
	Unpack(handler string, pkgs []string) ([]string, error)
}

type UnpackMirrorServer struct {
	BasicPipManager
	client       *docker.Client
	unpackMirror string
	depGraph     map[Package][]Package // package -> dependencies
	graphMtx     *sync.Mutex           // access mutex to depGraph
}

func NewUnpackMirrorServer(pipMirror string, unpackMirror string) (*UnpackMirrorServer, error) {
	var client *docker.Client
	if c, err := docker.NewClientFromEnv(); err != nil {
		return nil, err
	} else {
		client = c
	}

	absUnpackMirror, err := filepath.Abs(unpackMirror)
	if err != nil {
		return nil, err
	}

	// Read dependencies from file if exists
	depsFile := filepath.Join(absUnpackMirror, "deps.txt")
	depGraph := map[Package][]Package{}
	depList := [][]Package{}
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
				depList = append(depList, pkgs)
			}
		}
	}

	manager := &UnpackMirrorServer{
		BasicPipManager: *NewBasicPipManager(pipMirror),
		client:          client,
		unpackMirror:    absUnpackMirror,
		depGraph:        depGraph,
		graphMtx:        &sync.Mutex{},
	}

	return manager, nil
}

// getAllDeps gets the recursive dependencies of pkg and stores the result in allDeps.
func (m *UnpackMirrorServer) getAllDeps(pkg Package, allDeps map[Package]bool) error {
	if _, ok := allDeps[pkg]; ok {
		return nil
	}
	if deps, ok := m.depGraph[pkg]; !ok {
		return fmt.Errorf("[%v] has not been installed", pkg)
	} else if deps == nil {
		return fmt.Errorf("[%v] cannot be installed", pkg)
	} else {
		allDeps[pkg] = true
		for _, dep := range deps {
			if err := m.getAllDeps(dep, allDeps); err != nil {
				return fmt.Errorf("[%v] %v", pkg, err)
			}
		}
		return nil
	}
}

// GetAllDeps gets the recursive dependencies of pkg.
func (m *UnpackMirrorServer) GetAllDeps(pkg Package) (map[Package]bool, error) {
	allDeps := map[Package]bool{}
	if err := m.getAllDeps(pkg, allDeps); err != nil {
		return nil, err
	}
	return allDeps, nil
}

// prepare installs a package in the unpack mirror and archives it.
func (m *UnpackMirrorServer) prepare(pkg Package, taskChan chan bool, group *sync.WaitGroup, depsLog *log.Logger, commLog *log.Logger) {
	taskChan <- true
	defer group.Done()
	defer func() {
		<-taskChan
	}()

	m.graphMtx.Lock()
	if _, ok := m.depGraph[pkg]; ok {
		commLog.Printf("[%v] already installed\n", pkg)
		m.graphMtx.Unlock()
		return
	} else {
		commLog.Printf("[%v] installation start\n", pkg)
		m.depGraph[pkg] = nil
		m.graphMtx.Unlock()
	}

	pkgstr := pkg.String()

	installDir := filepath.Join(m.unpackMirror, "packages", pkg.installDir())
	if err := os.MkdirAll(installDir, os.ModeDir); err != nil {
		commLog.Printf("[%v] error during mkdir: %v\n", pkg, err)
		return
	}

	// installation directory inside container.
	pkgdir := fmt.Sprintf("/pip_packages/%s", pkgstr)
	binds := []string{
		fmt.Sprintf("%s:%s", installDir, pkgdir),
	}

	spec := fmt.Sprintf("%s==%s", pkg.Name, pkg.Version)

	container, err := m.client.CreateContainer(
		docker.CreateContainerOptions{
			Config: &docker.Config{
				Image: dockerutil.INSTALLER_IMAGE,
				Cmd: []string{
					"python",
					"pip_patched.py", "install",
					"-t", pkgdir,
					"-qqq",
					"-i", m.pipMirror,
					spec,
				},
			},
			HostConfig: &docker.HostConfig{
				Binds:          binds,
				ReadonlyRootfs: true,
				Tmpfs:          map[string]string{"/tmp": ""},
			},
		},
	)
	if err != nil {
		os.RemoveAll(installDir)
		commLog.Printf("[%v] fail to create installation container: %v\n", pkg, err)
		return
	}

	if err = m.client.StartContainer(container.ID, nil); err != nil {
		os.RemoveAll(installDir)
		commLog.Printf("[%v] fail to install package: %v\n", pkg, err)
		m.client.RemoveContainer(docker.RemoveContainerOptions{ID: container.ID})
		return
	}

	timeout := make(chan bool)
	exitcodeChan := make(chan int)
	errChan := make(chan error)

	go func() {
		time.Sleep(10 * time.Minute)
		timeout <- true
	}()

	go func() {
		if exitcode, err := m.client.WaitContainer(container.ID); err != nil {
			errChan <- err
		} else {
			exitcodeChan <- exitcode
		}
	}()

	select {
	case <-timeout:
		err := m.client.KillContainer(docker.KillContainerOptions{ID: container.ID})
		os.RemoveAll(installDir)
		if err != nil {
			commLog.Printf("[%v] fail to kill container %s when installation timeout: %v\n", pkg, container.ID, err)
		} else {
			commLog.Printf("[%v] installation timeout\n", pkg)
		}
		m.client.RemoveContainer(docker.RemoveContainerOptions{ID: container.ID})
		return
	case err = <-errChan:
		os.RemoveAll(installDir)
		commLog.Printf("[%v] error during installation: %v\n", pkg, err)
		m.client.RemoveContainer(docker.RemoveContainerOptions{ID: container.ID})
		return
	case exitcode := <-exitcodeChan:
		if exitcode != 0 {
			os.RemoveAll(installDir)
			var buf bytes.Buffer
			err = m.client.Logs(docker.LogsOptions{
				Container:   container.ID,
				ErrorStream: &buf,
				Follow:      true,
				Stderr:      true,
			})
			if err != nil {
				commLog.Printf("[%v] fail to get error logs from installation container: %v\n", pkg, err)
			} else {
				commLog.Printf("[%v] container exited with non-zero code %d: {stderr start}\n%s{stderr end}\n", pkg, exitcode, buf.String())
			}
			m.client.RemoveContainer(docker.RemoveContainerOptions{ID: container.ID})
			return
		}
	}

	var buf bytes.Buffer
	err = m.client.Logs(docker.LogsOptions{
		Container:    container.ID,
		OutputStream: &buf,
		Follow:       true,
		Stdout:       true,
	})
	if err != nil {
		os.RemoveAll(installDir)
		m.client.RemoveContainer(docker.RemoveContainerOptions{ID: container.ID})
		commLog.Printf("[%v] fail to get logs from installation container: %v\n", pkg, err)
		return
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

	m.client.RemoveContainer(docker.RemoveContainerOptions{ID: container.ID})

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
		commLog.Printf("[%v] error when creating package archive: %s\n", pkg, msg)
		return
	}

	resolved, err := m.Resolve(deps)
	if err != nil {
		os.RemoveAll(installDir)
		commLog.Printf("[%v] error during resolving dependency versions: %v\n", pkg, err)
		return
	}

	commLog.Printf("[%v] installation completed\n", pkg)

	m.depGraph[pkg] = resolved

	depsLog.Printf(pkg.String())
	for _, dep := range resolved {
		depsLog.Printf(" %v", dep)
	}
	depsLog.Printf("\n")

	for idx, p := range resolved {
		if p.Version == "" {
			m.depGraph[pkg] = nil
			commLog.Printf("[%v] cannot resolve dependency: %s\n", pkg, deps[idx])
		} else {
			go func() {
				group.Add(1)
				taskChan <- true
				go m.prepare(p, taskChan, group, depsLog, commLog)
			}()
		}
	}
}

// Prepare installs a list of package specifications and returns a list of
// remaining ones.
func (m *UnpackMirrorServer) Prepare(pkgs []string) ([]string, error) {
	remains := []string{}

	resolved, err := m.Resolve(pkgs)
	if err != nil {
		return nil, err
	}

	logPath := filepath.Join(m.unpackMirror, "offline_installer.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	defer logFile.Close()
	commLog := log.New(logFile, "", log.LstdFlags)

	depsPath := filepath.Join(m.unpackMirror, "deps.txt")
	depsFile, err := os.Create(depsPath)
	if err != nil {
		return nil, err
	}
	defer depsFile.Close()
	depsLog := log.New(depsFile, "", 0)

	group := &sync.WaitGroup{}
	NUM_THREADS := 4
	taskChan := make(chan bool, NUM_THREADS)

	for idx, pkg := range resolved {
		commLog.Printf("(%d/%d) Preparing package %v", idx+1, len(resolved), pkg)
		if pkg.Version == "" {
			commLog.Printf("[%s] version resolution fails", pkgs[idx])
			remains = append(remains, pkgs[idx])
		} else {
			group.Add(1)
			taskChan <- true
			go m.prepare(pkg, taskChan, group, depsLog, commLog)
		}
	}

	group.Wait()

	for idx, pkg := range resolved {
		if pkg.Version != "" {
			if _, err := m.GetAllDeps(pkg); err != nil {
				commLog.Printf("%v\n", err)
				remains = append(remains, pkgs[idx])
			}
		}
	}

	return remains, nil
}

// TODO: eviction
// Unpack decompresses a list of archived installed packages to a target directory.
func (m *UnpackMirrorServer) Unpack(targetDir string, pkgs []string) ([]string, error) {
	allDeps := map[Package]bool{}
	toInstall := []string{}

	if resolved, err := m.Resolve(pkgs); err != nil {
		return nil, err
	} else {
		for idx, pkg := range resolved {
			if pkg.Version == "" {
				fmt.Printf("specification cannot be resolved: %s\n", pkgs[idx])
				toInstall = append(toInstall, pkgs[idx])
			} else if deps, err := m.GetAllDeps(resolved[0]); err != nil {
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
		archive := filepath.Join(m.unpackMirror, "packages", pkg.installDir()) + ".tar.gz"

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
