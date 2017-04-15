package pip

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// Package identifies a package with its name and an exact version.
type Package struct {
	Name    string
	Version string
}

func (p Package) String() string {
	return fmt.Sprintf("%s,%s", p.Name, p.Version)
}

// installDir gets the installation directory of a package in the unpack mirror.
func (p Package) installDir() string {
	pkgstr := p.String()
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(pkgstr)))
	return filepath.Join(hash[:2], hash[2:4], hash[4:], pkgstr)
}

type PipManager interface {
	Script() string
	PipMirror() string
}

// Resolve resolves the exact version given a package specification.
func (m *PipManager) Resolve(specs []string) ([]Package, error) {
	slice := 500
	resolved := []Package{}
	for len(specs) > 0 {
		if len(specs) < 500 {
			slice = len(specs)
		}
		cmd := exec.Command("python", append([]string{
			m.Script(), "resolve", "-qqq", "-i", m.PipMirror(),
		}, specs[:slice]...)...)
		specs = specs[slice:]

		if output, err := cmd.Output(); err != nil {
			return nil, fmt.Errorf("fail to resolve packages: %s", string(err.(*exec.ExitError).Stderr))
		} else {
			scanner := bufio.NewScanner(bytes.NewBuffer(output))
			for scanner.Scan() {
				parts := strings.Split(scanner.Text(), ",")
				resolved = append(resolved, Package{
					Name:    strings.ToLower(parts[0]),
					Version: strings.ToLower(parts[1]),
				})
			}
		}
	}
	return resolved, nil
}

type BasicPipManager struct {
	script    string
	pipMirror string
}

func NewBasicPipManager(pipMirror string) *BasicPipManager {
	// TODO: better way to find the script
	script := filepath.Join(filepath.Dir(os.Args[0]), "..", "worker", "pip-manager", "scripts", "pip_patched.py")
	script, _ = filepath.Abs(script)

	if pipMirror == "" {
		pipMirror = "https://pypi.python.org/simple"
	}

	return &BasicPipManager{
		script:    script,
		pipMirror: pipMirror,
	}
}

func (m *BasicPipManager) Script() string {
	return m.script
}

func (m *BasicPipManager) PipMirror() string {
	return m.pipMirror
}
