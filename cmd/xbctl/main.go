package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"gopkg.in/yaml.v3"
)

const (
	defaultConfigPath      = "/etc/xboard-node/config.yml"
	defaultMetaPath        = "/etc/xboard-node/install-meta.json"
	defaultCredentialsPath = "/etc/xboard-node/credentials.env"
	defaultBinaryPath      = "/usr/local/bin/xboard-node"
	defaultCLIPath         = "/usr/local/bin/xbctl"
	serviceName            = "xboard-node"
	systemdServiceFilePath = "/etc/systemd/system/xboard-node.service"
	openrcInitScript       = "/etc/init.d/xboard-node"
	defaultInstallRoot = "/etc/xboard-node"
)

// Set via ldflags at build time: -X main.downloadBase=...
var downloadBase = "https://github.com/cedar2025/xboard-node/releases"

// initSystem returns "systemd", "openrc", or "unknown".
func initSystem() string {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if _, err2 := exec.LookPath("systemctl"); err2 == nil {
			return "systemd"
		}
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		return "openrc"
	}
	if _, err := os.Stat("/etc/init.d"); err == nil {
		return "openrc"
	}
	return "unknown"
}

// serviceFilePath returns the path for the service/init file.
func serviceFilePath() string {
	if initSystem() == "openrc" {
		return openrcInitScript
	}
	return systemdServiceFilePath
}

var (
	version   = "dev"
	buildTime = "unknown"
)

type instanceRow struct {
	ID      string `json:"id"`
	Mode    string `json:"mode"`
	Panel   string `json:"panel"`
	Target  string `json:"target"`
	Service string `json:"service"`
	Health  string `json:"health"`
}

type fileRootConfig struct {
	Log       *fileLogConfig     `yaml:"log,omitempty"`
	Kernel    *fileKernelConfig  `yaml:"kernel,omitempty"`
	Node      *fileNodeConfig    `yaml:"node,omitempty"`
	WS        *config.WSConfig   `yaml:"ws,omitempty"`
	Runtime   *fileRuntimeConfig `yaml:"runtime,omitempty"`
	Cert      *config.CertConfig `yaml:"cert,omitempty"`
	Instances []fileInstance      `yaml:"instances,omitempty"`
}

type fileInstance struct {
	ID         string             `yaml:"id,omitempty"`
	Panel      filePanelConfig    `yaml:"panel"`
	Node       *fileNodeConfig    `yaml:"node,omitempty"`
	Kernel     fileKernelConfig   `yaml:"kernel"`
	Log        fileLogConfig      `yaml:"log"`
	Runtime    *fileRuntimeConfig `yaml:"runtime,omitempty"`
	HealthPort int                `yaml:"health_port,omitempty"`
	Machine    *fileMachineConfig `yaml:"machine,omitempty"`
	Standalone map[string]any     `yaml:"standalone,omitempty"`
	Cert       *config.CertConfig `yaml:"cert,omitempty"`
	WS         *config.WSConfig   `yaml:"ws,omitempty"`
	Nodes      []config.NodeEntry `yaml:"nodes,omitempty"`
}

type filePanelConfig struct {
	URL      string `yaml:"url"`
	TokenEnv string `yaml:"token_env,omitempty"`
	NodeID   int    `yaml:"node_id,omitempty"`
	NodeType string `yaml:"node_type,omitempty"`
}

type fileMachineConfig struct {
	MachineID int    `yaml:"machine_id"`
	TokenEnv  string `yaml:"token_env,omitempty"`
}

type fileNodeConfig struct {
	PushInterval         int `yaml:"push_interval,omitempty"`
	PullInterval         int `yaml:"pull_interval,omitempty"`
	TrackInterval        int `yaml:"track_interval,omitempty"`
	DeviceReportInterval int `yaml:"device_report_interval,omitempty"`
}

type fileKernelConfig struct {
	ConfigDir    string           `yaml:"config_dir"`
	LogLevel     string           `yaml:"log_level,omitempty"`
	GeoDataDir   string           `yaml:"geo_data_dir,omitempty"`
	CustomConfig string           `yaml:"custom_config,omitempty"`
	CustomRoute  []map[string]any `yaml:"custom_route,omitempty"`
	CustomOut    []map[string]any `yaml:"custom_outbound,omitempty"`
}

type fileLogConfig struct {
	Level  string `yaml:"level,omitempty"`
	Output string `yaml:"output,omitempty"`
}

type fileRuntimeConfig struct {
	GoMemLimit  string `yaml:"gomemlimit,omitempty"`
	GoGCPercent int    `yaml:"gogc,omitempty"`
}

type instanceSummary struct {
	ID         string `json:"id"`
	PanelURL   string `json:"panel_url"`
	Mode       string `json:"mode"`
	NodeID     *int   `json:"node_id"`
	MachineID  *int   `json:"machine_id"`
	HealthPort int    `json:"health_port"`
}

type installMeta struct {
	ConfigMode       string            `json:"config_mode"`
	Version          string            `json:"version"`
	LatestInstanceID string            `json:"latest_instance_id"`
	InstanceCount    int               `json:"instance_count"`
	Instances        []instanceSummary `json:"instances"`
	UpdatedAt        string            `json:"updated_at"`
}

func loadInstallMeta(path string) (*installMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	meta := &installMeta{}
	if err := json.Unmarshal(data, meta); err != nil {
		return nil, fmt.Errorf("parse install meta: %w", err)
	}
	return meta, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}
	switch args[0] {
	case "status":
		return runStatus()
	case "list":
		return runList(args[1:])
	case "instance":
		return runInstance(args[1:])
	case "service":
		return runService(args[1:])
	case "logs", "log":
		return runService([]string{"logs"})
	case "health":
		return runHealth()
	case "bind":
		return runBind(args[1:])
	case "bind-node":
		return runBind(append([]string{"add-node"}, args[1:]...))
	case "bind-machine":
		return runBind(append([]string{"add-machine"}, args[1:]...))
	case "unbind-node":
		return runBind(append([]string{"remove-node"}, args[1:]...))
	case "unbind-machine":
		return runBind(append([]string{"remove-machine"}, args[1:]...))
	case "start", "stop", "restart", "enable", "disable":
		return runService(args)
	case "upgrade":
		return runUpgrade(args[1:])
	case "uninstall":
		return runUninstall(args[1:])
	case "version", "-v", "--version":
		fmt.Printf("xbctl %s (built %s)\n", version, buildTime)
		return nil
	case "config":
		return runConfig(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func printUsage() {
	fmt.Println(`xbctl commands:
  xbctl help
  xbctl status
  xbctl list [--output text|json]
  xbctl instance list [--output text|json]
  xbctl instance get <id> [--output text|json]
  xbctl config init --mode node|machine --panel-url URL --token TOKEN [flags]
  xbctl config health-port [--config PATH]
  xbctl service status|start|stop|restart|enable|disable|logs
  xbctl health
  xbctl bind add-node --panel-url URL --token TOKEN --node-id ID [--node-type TYPE]
  xbctl bind add-machine --panel-url URL --token TOKEN --machine-id ID
  xbctl bind remove <instance-id>
  xbctl bind remove-node --panel URL --node-id ID
  xbctl bind remove-machine --panel URL --machine-id ID
  xbctl upgrade [--version VERSION]
  xbctl uninstall [--purge] [--yes]
  xbctl version

shortcuts:
  xbctl start|stop|restart        = xbctl service start|stop|restart
  xbctl log|logs                  = xbctl service logs
  xbctl bind-node ...             = xbctl bind add-node ...
  xbctl bind-machine ...          = xbctl bind add-machine ...
  xbctl unbind-node ...           = xbctl bind remove-node ...
  xbctl unbind-machine ...        = xbctl bind remove-machine ...`)
}

func runStatus() error {
	fmt.Println("xboard-node status")
	fmt.Println()

	// Version from install-meta.json
	ver := "unknown"
	if meta, err := loadInstallMeta(defaultMetaPath); err == nil {
		ver = meta.Version
	}
	fmt.Printf("  version:  %s\n", ver)

	// Service status
	svc := systemctlState()
	fmt.Printf("  service:  %s\n", svc)

	// Health
	health := instanceAwareHealth()
	fmt.Printf("  health:   %s\n", health)
	fmt.Println()

	// Instance list
	rows, err := collectInstanceRows()
	if err != nil {
		fmt.Printf("  (no instances found: %v)\n", err)
		return nil
	}
	return printRows(rows, "text")
}

func runList(args []string) error {
	output := parseOutput(args)
	rows, err := collectInstanceRows()
	if err != nil {
		return err
	}
	return printRows(rows, output)
}

func runInstance(args []string) error {
	if len(args) == 0 {
		return runList(nil)
	}
	if args[0] == "list" {
		return runList(args[1:])
	}
	if args[0] != "get" {
		return fmt.Errorf("unknown instance command: %s", args[0])
	}
	if len(args) < 2 {
		return errors.New("usage: xbctl instance get <id> [--output text|json]")
	}
	id := args[1]
	output := parseOutput(args[2:])
	rows, err := collectInstanceRows()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.ID == id {
			return printRows([]instanceRow{row}, output)
		}
	}
	return fmt.Errorf("instance not found: %s", id)
}

func runService(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: xbctl service <status|start|stop|restart|enable|disable|logs>")
	}
	sub := args[0]
	rest := args[1:]
	init := initSystem()
	switch sub {
	case "status":
		if init == "openrc" {
			return runCommand("sudo", append([]string{"rc-service", serviceName, "status"}, rest...)...)
		}
		return runCommand("sudo", append([]string{"systemctl", "status", serviceName+".service", "--no-pager"}, rest...)...)
	case "start", "stop", "restart":
		if init == "openrc" {
			return runCommand("sudo", append([]string{"rc-service", serviceName, sub}, rest...)...)
		}
		return runCommand("sudo", append([]string{"systemctl", sub, serviceName}, rest...)...)
	case "enable":
		if init == "openrc" {
			return runCommand("sudo", "rc-update", "add", serviceName, "default")
		}
		return runCommand("sudo", "systemctl", "enable", serviceName)
	case "disable":
		if init == "openrc" {
			return runCommand("sudo", "rc-update", "del", serviceName, "default")
		}
		return runCommand("sudo", "systemctl", "disable", serviceName)
	case "logs":
		if init == "openrc" {
			logFile := "/var/log/xboard-node.log"
			if len(rest) == 0 {
				return runCommand("tail", "-f", logFile)
			}
			return runCommand("tail", append(rest, logFile)...)
		}
		if len(rest) == 0 {
			rest = []string{"-f"}
		}
		return runCommand("sudo", append([]string{"journalctl", "-u", serviceName + ".service"}, rest...)...)
	default:
		return fmt.Errorf("unknown service command: %s", sub)
	}
}

func runHealth() error {
	h := instanceAwareHealth()
	fmt.Println(h)
	if h == "down" {
		return errors.New("health check failed")
	}
	return nil
}

func runBind(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: xbctl bind <add-node|add-machine|remove-node|remove-machine> ...")
	}
	if err := ensureRoot("bind"); err != nil {
		return err
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "add-node":
		return runBindAdd("node", rest)
	case "add-machine":
		return runBindAdd("machine", rest)
	case "remove-node":
		panel, nodeID, err := parseRemoveNodeArgs(rest)
		if err != nil {
			return err
		}
		return removeBinding(panel, nodeID, 0, "")
	case "remove-machine":
		panel, machineID, err := parseRemoveMachineArgs(rest)
		if err != nil {
			return err
		}
		return removeBinding(panel, 0, machineID, "")
	case "remove":
		if len(rest) == 0 {
			return errors.New("usage: xbctl bind remove <instance-id>")
		}
		return removeBinding("", 0, 0, rest[0])
	default:
		return fmt.Errorf("unknown bind command: %s", sub)
	}
}

func runBindAdd(mode string, args []string) error {
	// Build configInit args from bind args
	initArgs := []string{
		"--mode", mode,
		"--config", defaultConfigPath,
		"--output", defaultConfigPath,
		"--credentials-in", defaultCredentialsPath,
		"--credentials-out", defaultCredentialsPath,
		"--meta", defaultMetaPath,
		"--install-root", defaultInstallRoot,
	}
	// Pass through remaining args (--panel-url, --token, --node-id, --machine-id, --kernel, etc.)
	initArgs = append(initArgs, args...)

	if err := runConfigInit(initArgs); err != nil {
		return fmt.Errorf("bind failed: %w", err)
	}
	// Restart service to pick up new config
	fmt.Println("Restarting service...")
	var err error
	if initSystem() == "openrc" {
		err = runCommand("rc-service", serviceName, "restart")
	} else {
		err = runCommand("systemctl", "restart", serviceName)
	}
	if err != nil {
		return fmt.Errorf("service restart failed: %w", err)
	}
	fmt.Println("Binding added successfully")
	return nil
}

func runUpgrade(args []string) error {
	if err := ensureRoot("upgrade"); err != nil {
		return err
	}

	version := "latest"
	for i := 0; i < len(args); i++ {
		if args[i] == "--version" && i+1 < len(args) {
			version = args[i+1]
			i++
		}
	}

	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("unsupported architecture: %s", arch)
	}

	fmt.Println("Starting upgrade...")

	binaryDir := filepath.Dir(defaultBinaryPath)
	cliDir := filepath.Dir(defaultCLIPath)
	newBinary := filepath.Join(binaryDir, ".xboard-node.new")
	newCLI := filepath.Join(cliDir, ".xbctl.new")

	binaryURL := resolveDownloadURL(fmt.Sprintf("xboard-node-linux-%s", arch), version)
	cliURL := resolveDownloadURL(fmt.Sprintf("xbctl-linux-%s", arch), version)

	fmt.Printf("Downloading %s...\n", binaryURL)
	if err := downloadFile(binaryURL, newBinary); err != nil {
		return fmt.Errorf("download binary: %w", err)
	}

	fmt.Printf("Downloading %s...\n", cliURL)
	if err := downloadFile(cliURL, newCLI); err != nil {
		os.Remove(newBinary)
		return fmt.Errorf("download xbctl: %w", err)
	}

	if err := os.Chmod(newBinary, 0o755); err != nil {
		return cleanupFiles(newBinary, newCLI, fmt.Errorf("chmod binary: %w", err))
	}
	if err := os.Chmod(newCLI, 0o755); err != nil {
		return cleanupFiles(newBinary, newCLI, fmt.Errorf("chmod xbctl: %w", err))
	}

	// Validate downloaded binaries
	if out, err := exec.Command(newBinary, "-v").CombinedOutput(); err != nil {
		return cleanupFiles(newBinary, newCLI, fmt.Errorf("binary version check failed: %s", string(out)))
	}
	if out, err := exec.Command(newCLI, "version").CombinedOutput(); err != nil {
		return cleanupFiles(newBinary, newCLI, fmt.Errorf("xbctl version check failed: %s", string(out)))
	}

	// Backup existing binaries
	backupBinary := defaultBinaryPath + ".bak"
	backupCLI := defaultCLIPath + ".bak"
	// Backup existing binaries
	if fileExists(defaultBinaryPath) {
		if err := copyFile(defaultBinaryPath, backupBinary); err != nil {
			return cleanupFiles(newBinary, newCLI, fmt.Errorf("backup binary: %w", err))
		}
	}
	if fileExists(defaultCLIPath) {
		if err := copyFile(defaultCLIPath, backupCLI); err != nil {
			return cleanupFiles(newBinary, newCLI, fmt.Errorf("backup xbctl: %w", err))
		}
	}

	// Atomic rename
	if err := os.Rename(newBinary, defaultBinaryPath); err != nil {
		return cleanupFiles(newBinary, newCLI, fmt.Errorf("replace binary: %w", err))
	}
	if err := os.Rename(newCLI, defaultCLIPath); err != nil {
		if fileExists(backupBinary) {
			os.Rename(backupBinary, defaultBinaryPath)
		}
		os.Remove(newCLI)
		return fmt.Errorf("replace xbctl: %w", err)
	}

	// Recreate /usr/bin/xbctl symlink
	os.Remove("/usr/bin/xbctl")
	os.Symlink(defaultCLIPath, "/usr/bin/xbctl")

	// Restart service
	fmt.Println("Restarting service...")
	init := initSystem()
	if init == "systemd" {
		runCommand("systemctl", "daemon-reload")
	}
	restartCmd := func() error {
		if init == "openrc" {
			return runCommand("rc-service", serviceName, "restart")
		}
		return runCommand("systemctl", "restart", serviceName)
	}
	if err := restartCmd(); err != nil {
		fmt.Println("Restart failed, rolling back...")
		rollbackOK := true
		if fileExists(backupBinary) {
			if e := os.Rename(backupBinary, defaultBinaryPath); e != nil {
				fmt.Printf("Warning: rollback binary failed: %v\n", e)
				rollbackOK = false
			}
		}
		if fileExists(backupCLI) {
			if e := os.Rename(backupCLI, defaultCLIPath); e != nil {
				fmt.Printf("Warning: rollback xbctl failed: %v\n", e)
				rollbackOK = false
			}
		}
		if init == "systemd" {
			runCommand("systemctl", "daemon-reload")
		}
		if e := restartCmd(); e != nil {
			return fmt.Errorf("upgrade and rollback restart both failed: %w", e)
		}
		if rollbackOK {
			return errors.New("upgrade failed: service restart failed, rolled back successfully")
		}
		return errors.New("upgrade failed: partial rollback, check binary state manually")
	}

	// Clean up backups
	os.Remove(backupBinary)
	os.Remove(backupCLI)

	// Update install-meta.json
	newVer := "unknown"
	if out, err := exec.Command(defaultBinaryPath, "-v").CombinedOutput(); err == nil {
		newVer = strings.TrimSpace(string(out))
	}
	if root, err := loadWritableRootConfig(defaultConfigPath); err == nil {
		instances, _ := root.NormalizeInstances()
		writeInstallMetaVersioned(defaultMetaPath, root, newVer, latestInstanceID(instances))
	}

	fmt.Printf("Upgrade complete (version: %s)\n", newVer)
	return nil
}

func runUninstall(args []string) error {
	if err := ensureRoot("uninstall"); err != nil {
		return err
	}

	purge := false
	yes := false
	for _, a := range args {
		switch a {
		case "--purge":
			purge = true
		case "--yes", "-y":
			yes = true
		}
	}

	if !yes {
		fmt.Print("Proceed with uninstall? [y/N]: ")
		var answer string
		fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" {
			fmt.Println("Uninstall cancelled")
			return nil
		}
	}

	var warnings []string

	// Stop and disable service
	svcFile := serviceFilePath()
	init := initSystem()
	if fileExists(svcFile) {
		var stopErr, disableErr error
		if init == "openrc" {
			stopErr = runCommand("rc-service", serviceName, "stop")
			disableErr = runCommand("rc-update", "del", serviceName, "default")
		} else {
			stopErr = runCommand("systemctl", "stop", serviceName)
			disableErr = runCommand("systemctl", "disable", serviceName)
		}
		if stopErr != nil {
			warnings = append(warnings, fmt.Sprintf("stop service: %v", stopErr))
		}
		if disableErr != nil {
			warnings = append(warnings, fmt.Sprintf("disable service: %v", disableErr))
		}
		if err := os.Remove(svcFile); err != nil {
			warnings = append(warnings, fmt.Sprintf("remove service file: %v", err))
		}
		if init == "systemd" {
			runCommand("systemctl", "daemon-reload")
		}
	}

	// Remove binaries
	// Remove binaries and symlinks
	for _, p := range []string{defaultBinaryPath, defaultCLIPath, "/usr/bin/xbctl"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("remove %s: %v", p, err))
		}
	}

	if purge {
		if err := os.RemoveAll(defaultInstallRoot); err != nil {
			warnings = append(warnings, fmt.Sprintf("remove %s: %v", defaultInstallRoot, err))
		} else {
			fmt.Printf("Removed %s\n", defaultInstallRoot)
		}
	} else {
		os.Remove(defaultMetaPath)
		fmt.Printf("Config preserved under %s\n", defaultInstallRoot)
	}

	if len(warnings) > 0 {
		fmt.Println("Uninstall completed with warnings:")
		for _, w := range warnings {
			fmt.Printf("  - %s\n", w)
		}
		return nil
	}

	fmt.Println("Uninstall complete")
	return nil
}

func ensureRoot(cmd string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s requires root privileges; run with sudo", cmd)
	}
	return nil
}

func resolveDownloadURL(artifact, version string) string {
	if version == "latest" {
		return downloadBase + "/latest/download/" + artifact
	}
	return downloadBase + "/download/" + version + "/" + artifact
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func cleanupFiles(a, b string, err error) error {
	os.Remove(a)
	os.Remove(b)
	return err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func parseOutput(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--output" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(args[i], "--output=") {
			return strings.TrimPrefix(args[i], "--output=")
		}
	}
	return "text"
}

func parseRemoveNodeArgs(args []string) (string, int, error) {
	var panel string
	var nodeID int
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--panel", "-a", "--api":
			if i+1 >= len(args) {
				return "", 0, errors.New("missing value for --panel")
			}
			panel = args[i+1]
			i++
		case "--node-id", "-n":
			if i+1 >= len(args) {
				return "", 0, errors.New("missing value for --node-id")
			}
			var err error
			nodeID, err = parsePositiveInt(args[i+1], "node-id")
			if err != nil {
				return "", 0, err
			}
			i++
		default:
			return "", 0, fmt.Errorf("unknown remove-node arg: %s", args[i])
		}
	}
	if strings.TrimSpace(panel) == "" || nodeID <= 0 {
		return "", 0, errors.New("usage: xbctl bind remove-node --panel URL --node-id ID")
	}
	return strings.TrimSpace(panel), nodeID, nil
}

func parseRemoveMachineArgs(args []string) (string, int, error) {
	var panel string
	var machineID int
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--panel", "-a", "--api":
			if i+1 >= len(args) {
				return "", 0, errors.New("missing value for --panel")
			}
			panel = args[i+1]
			i++
		case "--machine-id":
			if i+1 >= len(args) {
				return "", 0, errors.New("missing value for --machine-id")
			}
			var err error
			machineID, err = parsePositiveInt(args[i+1], "machine-id")
			if err != nil {
				return "", 0, err
			}
			i++
		default:
			return "", 0, fmt.Errorf("unknown remove-machine arg: %s", args[i])
		}
	}
	if strings.TrimSpace(panel) == "" || machineID <= 0 {
		return "", 0, errors.New("usage: xbctl bind remove-machine --panel URL --machine-id ID")
	}
	return strings.TrimSpace(panel), machineID, nil
}

func parsePositiveInt(raw string, field string) (int, error) {
	var value int
	_, err := fmt.Sscanf(raw, "%d", &value)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid %s: %s", field, raw)
	}
	return value, nil
}

func removeBinding(panelURL string, nodeID int, machineID int, instanceID string) error {
	root, err := loadWritableRootConfig(defaultConfigPath)
	if err != nil {
		return err
	}
	instances := normalizeRootInstances(root)
	if len(instances) == 0 {
		return errors.New("no instances configured")
	}

	kept := make([]config.Config, 0, len(instances))
	removed := make([]config.Config, 0, 1)
	for _, inst := range instances {
		var matched bool
		if instanceID != "" {
			// Match by instance ID
			id, _ := inst.AutoInstanceID()
			matched = id == instanceID || inst.InstanceID == instanceID
		} else {
			matched = strings.TrimSpace(inst.Panel.URL) == strings.TrimSpace(panelURL)
			if nodeID > 0 {
				matched = matched && !inst.IsMachineMode() && inst.Panel.NodeID == nodeID
			}
			if machineID > 0 {
				matched = matched && inst.IsMachineMode() && inst.Machine != nil && inst.Machine.MachineID == machineID
			}
		}
		if matched {
			removed = append(removed, inst)
			continue
		}
		kept = append(kept, inst)
	}
	if len(removed) == 0 {
		if instanceID != "" {
			return fmt.Errorf("binding not found: id=%s", instanceID)
		}
		if nodeID > 0 {
			return fmt.Errorf("binding not found: panel=%s node_id=%d", panelURL, nodeID)
		}
		return fmt.Errorf("binding not found: panel=%s machine_id=%d", panelURL, machineID)
	}
	if len(kept) == 0 {
		// Last binding removed — stop the service to prevent crash-loop
		root.Instances = nil
		if err := writeRootConfig(defaultConfigPath, root); err != nil {
			return err
		}
		if err := pruneCredentialKeys(defaultCredentialsPath, removed); err != nil {
			return err
		}
		if err := writeInstallMeta(defaultMetaPath, root); err != nil {
			return err
		}
		if initSystem() == "openrc" {
			runCommand("rc-service", serviceName, "stop")
		} else {
			runCommand("systemctl", "stop", serviceName)
		}
		fmt.Printf("removed %d binding(s)\n", len(removed))
		fmt.Println("All bindings removed. Service stopped.")
		fmt.Println("Use 'xbctl bind add-node/add-machine' to add a new binding, or 'xbctl uninstall' to fully uninstall.")
		return nil
	}

	root.Instances = kept
	// Preserve top-level shared settings (log, kernel, etc.) — instances inherit from these.
	if err := writeRootConfig(defaultConfigPath, root); err != nil {
		return err
	}
	if err := pruneCredentialKeys(defaultCredentialsPath, removed); err != nil {
		return err
	}
	if err := writeInstallMeta(defaultMetaPath, root); err != nil {
		return err
	}
	var svcRestartErr error
	if initSystem() == "openrc" {
		svcRestartErr = runCommand("rc-service", serviceName, "restart")
	} else {
		svcRestartErr = runCommand("systemctl", "restart", serviceName)
	}
	if svcRestartErr != nil {
		return svcRestartErr
	}
	fmt.Printf("removed %d binding(s)\n", len(removed))
	return nil
}

func loadWritableRootConfig(path string) (*config.RootConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	rc := &config.RootConfig{}
	if err := yaml.Unmarshal(data, rc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if len(rc.Instances) == 0 {
		legacy := &config.Config{}
		if err := yaml.Unmarshal(data, legacy); err != nil {
			return nil, fmt.Errorf("parse legacy config: %w", err)
		}
		rc.Config = *legacy
	}
	return rc, nil
}

func normalizeRootInstances(root *config.RootConfig) []config.Config {
	if len(root.Instances) > 0 {
		return append([]config.Config(nil), root.Instances...)
	}
	// Only treat legacy single-config mode if the embedded Config is valid
	if root.Config.Panel.URL != "" {
		return []config.Config{root.Config}
	}
	return nil
}

func writeRootConfig(path string, root *config.RootConfig) error {
	instances := root.Instances
	if len(instances) == 0 && root.Config.Panel.URL != "" {
		instances = []config.Config{root.Config}
	}
	out := fileRootConfig{Instances: make([]fileInstance, 0, len(instances))}

	// Preserve top-level shared settings so instances can inherit them.
	p := &root.Config
	if p.Log.Level != "" || p.Log.Output != "" {
		out.Log = &fileLogConfig{Level: p.Log.Level, Output: p.Log.Output}
	}
	if p.Kernel.LogLevel != "" {
		out.Kernel = &fileKernelConfig{LogLevel: p.Kernel.LogLevel}
	}
	if p.Node.PushInterval != 0 || p.Node.PullInterval != 0 || p.Node.TrackInterval != 0 || p.Node.DeviceReportInterval != 0 {
		out.Node = &fileNodeConfig{
			PushInterval:         p.Node.PushInterval,
			PullInterval:         p.Node.PullInterval,
			TrackInterval:        p.Node.TrackInterval,
			DeviceReportInterval: p.Node.DeviceReportInterval,
		}
	}
	if p.Runtime.GoMemLimit != "" || p.Runtime.GoGCPercent != 0 {
		out.Runtime = &fileRuntimeConfig{GoMemLimit: p.Runtime.GoMemLimit, GoGCPercent: p.Runtime.GoGCPercent}
	}
	if p.WS.StatusInterval != 0 || p.WS.HandshakeTimeout != 0 || p.WS.BackoffInitial != 0 {
		out.WS = &p.WS
	}
	if p.Cert.CertMode != "" || p.Cert.Domain != "" || p.Cert.CertFile != "" || p.Cert.AutoTLS {
		out.Cert = &p.Cert
	}

	for _, inst := range instances {
		fi := fileInstance{
			ID: inst.InstanceID,
			Panel: filePanelConfig{
				URL:      inst.Panel.URL,
				TokenEnv: inst.Panel.TokenEnv,
				NodeID:   inst.Panel.NodeID,
				NodeType: inst.Panel.NodeType,
			},
			Kernel: fileKernelConfig{
				ConfigDir:    inst.Kernel.ConfigDir,
				LogLevel:     inst.Kernel.LogLevel,
				GeoDataDir:   inst.Kernel.GeoDataDir,
				CustomConfig: inst.Kernel.CustomConfig,
				CustomRoute:  inst.Kernel.CustomRoute,
				CustomOut:    inst.Kernel.CustomOutbound,
			},
			Log: fileLogConfig{
				Level:  inst.Log.Level,
				Output: inst.Log.Output,
			},
			HealthPort: inst.HealthPort,
		}
		if !inst.IsMachineMode() && (inst.Node.PushInterval != 0 || inst.Node.PullInterval != 0 || inst.Node.TrackInterval != 0 || inst.Node.DeviceReportInterval != 0) {
			fi.Node = &fileNodeConfig{
				PushInterval:         inst.Node.PushInterval,
				PullInterval:         inst.Node.PullInterval,
				TrackInterval:        inst.Node.TrackInterval,
				DeviceReportInterval: inst.Node.DeviceReportInterval,
			}
		}
		if inst.Runtime.GoMemLimit != "" || inst.Runtime.GoGCPercent != 0 {
			fi.Runtime = &fileRuntimeConfig{
				GoMemLimit:  inst.Runtime.GoMemLimit,
				GoGCPercent: inst.Runtime.GoGCPercent,
			}
		}
		if inst.IsMachineMode() && inst.Machine != nil {
			fi.Machine = &fileMachineConfig{
				MachineID: inst.Machine.MachineID,
				TokenEnv:  inst.Machine.TokenEnv,
			}
			fi.Panel.NodeID = 0
			fi.Panel.NodeType = ""
		}
		if inst.Cert.CertMode != "" || inst.Cert.Domain != "" || inst.Cert.CertFile != "" || inst.Cert.AutoTLS {
			fi.Cert = &inst.Cert
		}
		if inst.WS.StatusInterval != 0 || inst.WS.HandshakeTimeout != 0 || inst.WS.BackoffInitial != 0 {
			fi.WS = &inst.WS
		}
		if len(inst.Nodes) > 0 {
			fi.Nodes = inst.Nodes
		}
		out.Instances = append(out.Instances, fi)
	}
	data, err := yaml.Marshal(&out)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

func pruneCredentialKeys(path string, removed []config.Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read credentials: %w", err)
	}
	removeKeys := map[string]struct{}{}
	for _, inst := range removed {
		if env := strings.TrimSpace(inst.Panel.TokenEnv); env != "" {
			removeKeys[env] = struct{}{}
		}
		if inst.Machine != nil {
			if env := strings.TrimSpace(inst.Machine.TokenEnv); env != "" {
				removeKeys[env] = struct{}{}
			}
		}
	}
	lines := strings.Split(string(data), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		key := trimmed
		if idx := strings.Index(trimmed, "="); idx >= 0 {
			key = trimmed[:idx]
		}
		if _, ok := removeKeys[key]; ok {
			continue
		}
		kept = append(kept, line)
	}
	output := strings.Join(kept, "\n")
	if output != "" {
		output += "\n"
	}
	return os.WriteFile(path, []byte(output), 0o600)
}

func writeInstallMeta(path string, root *config.RootConfig) error {
	ver := "unknown"
	if meta, err := loadInstallMeta(path); err == nil && strings.TrimSpace(meta.Version) != "" {
		ver = meta.Version
	}
	return writeInstallMetaVersioned(path, root, ver, "")
}

func instanceMode(inst config.Config) string {
	if inst.IsMachineMode() {
		return "machine"
	}
	return "node"
}

func collectInstanceRows() ([]instanceRow, error) {
	rows, err := collectRowsFromMeta()
	if err == nil && len(rows) > 0 {
		return rows, nil
	}
	return collectRowsFromConfig()
}

func collectRowsFromMeta() ([]instanceRow, error) {
	meta, err := loadInstallMeta(defaultMetaPath)
	if err != nil {
		return nil, err
	}
	serviceStatus := systemctlState()
	healthStatus := healthStatus()
	rows := make([]instanceRow, 0, len(meta.Instances))
	for _, inst := range meta.Instances {
		rows = append(rows, instanceRow{
			ID:      inst.ID,
			Mode:    inst.Mode,
			Panel:   inst.PanelURL,
			Target:  formatTarget(inst.NodeID, inst.MachineID),
			Service: serviceStatus,
			Health:  healthStatus,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, nil
}

func collectRowsFromConfig() ([]instanceRow, error) {
	root, err := config.LoadRoot(defaultConfigPath)
	if err != nil {
		return nil, err
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		return nil, err
	}
	serviceStatus := systemctlState()
	healthStatus := healthStatus()
	rows := make([]instanceRow, 0, len(instances))
	for _, inst := range instances {
		mode := "node"
		if inst.IsMachineMode() {
			mode = "machine"
		}
		rows = append(rows, instanceRow{
			ID:      inst.InstanceID,
			Mode:    mode,
			Panel:   inst.Panel.URL,
			Target:  formatTarget(intPtr(inst.Panel.NodeID), machineIDPtr(inst)),
			Service: serviceStatus,
			Health:  healthStatus,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, nil
}

func printRows(rows []instanceRow, output string) error {
	if output == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tMODE\tPANEL\tTARGET\tSERVICE\tHEALTH")
	for _, row := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", row.ID, row.Mode, row.Panel, row.Target, row.Service, row.Health)
	}
	tw.Flush()
	_, err := fmt.Print(buf.String())
	return err
}

func systemctlState() string {
	if initSystem() == "openrc" {
		cmd := exec.Command("rc-service", serviceName, "status")
		if err := cmd.Run(); err == nil {
			return "active"
		}
		// check if the init script exists at all
		if _, err := os.Stat(openrcInitScript); err != nil {
			return "not-installed"
		}
		return "inactive"
	}
	cmd := exec.Command("systemctl", "is-active", serviceName)
	out, err := cmd.CombinedOutput()
	state := strings.TrimSpace(string(out))
	if state != "" {
		return state
	}
	if err != nil {
		return "unknown"
	}
	return state
}

func healthStatus() string {
	return instanceAwareHealth()
}

func instanceAwareHealth() string {
	port := 0
	if meta, err := loadInstallMeta(defaultMetaPath); err == nil {
		for _, inst := range meta.Instances {
			if inst.HealthPort > 0 {
				port = inst.HealthPort
				break
			}
		}
	}
	if port == 0 {
		if root, err := loadWritableRootConfig(defaultConfigPath); err == nil {
			// Check top-level health_port first (inherited by all instances)
			if root.HealthPort > 0 {
				port = root.HealthPort
			}
			if port == 0 {
				instances, _ := root.NormalizeInstances()
				for _, inst := range instances {
					if inst.HealthPort > 0 {
						port = inst.HealthPort
						break
					}
				}
			}
		}
	}
	if port == 0 {
		return "disabled"
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "down"
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		return "ok"
	}
	return "down"
}

func formatTarget(nodeID *int, machineID *int) string {
	if nodeID != nil && *nodeID > 0 {
		return fmt.Sprintf("node_id=%d", *nodeID)
	}
	if machineID != nil && *machineID > 0 {
		return fmt.Sprintf("machine_id=%d", *machineID)
	}
	return ""
}

func intPtr(v int) *int {
	if v <= 0 {
		return nil
	}
	vv := v
	return &vv
}

func latestInstanceID(instances []*config.Config) string {
	if len(instances) > 0 {
		id, _ := instances[len(instances)-1].AutoInstanceID()
		return id
	}
	return ""
}

func regenerateServiceFile() error {
	if initSystem() == "openrc" {
		script := `#!/sbin/openrc-run

description="Xboard Node Backend"
command="/usr/local/bin/xboard-node"
command_args="-c /etc/xboard-node/config.yml"
command_background=true
pidfile="/run/xboard-node.pid"
output_log="/var/log/xboard-node.log"
error_log="/var/log/xboard-node.log"

depend() {
    need net
    after firewall
}

start_pre() {
    if [ -f /etc/xboard-node/credentials.env ]; then
        set -a
        . /etc/xboard-node/credentials.env
        set +a
    fi
    touch "$output_log"
}
`
		return os.WriteFile(openrcInitScript, []byte(script), 0o755)
	}
	unit := fmt.Sprintf(`[Unit]
Description=Xboard Node Backend
Documentation=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
EnvironmentFile=-%s
ExecStart=%s -c %s
Restart=always
RestartSec=5
LimitNOFILE=1048576
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, strings.TrimSuffix(downloadBase, "/releases"), defaultInstallRoot, defaultCredentialsPath, defaultBinaryPath, defaultConfigPath)
	return os.WriteFile(systemdServiceFilePath, []byte(unit), 0o644)
}

func machineIDPtr(cfg *config.Config) *int {
	if cfg.Machine == nil || cfg.Machine.MachineID <= 0 {
		return nil
	}
	vv := cfg.Machine.MachineID
	return &vv
}

// ── config subcommand ─────────────────────────────────────────────────

func runConfig(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: xbctl config <init|health-port>")
	}
	switch args[0] {
	case "init":
		return runConfigInit(args[1:])
	case "health-port":
		return runConfigHealthPort(args[1:])
	default:
		return fmt.Errorf("unknown config command: %s", args[0])
	}
}

// runConfigInit generates/merges an instance into config.yml, writes
// credentials.env and install-meta.json. It replaces the Python PY_INST,
// PY_CFG, PY_ENV, and PY_META heredoc blocks in install.sh.
//
// Output (stdout, one per line):
//
//	INSTANCE_ID=<generated-id>
//	ENV_KEY=<credential-env-var-name>
func runConfigInit(args []string) error {
	var (
		configIn       string
		configOut      string
		credentialsIn  string
		credentialsOut string
		metaPath       string
		mode           string
		panelURL       string
		nodeID         int
		nodeType       string
		machineID      int
		healthPort     int
		gomemlimit     string
		gogc           int
		installRoot    string
		token          string
		releaseVersion string
	)

	for i := 0; i < len(args); i++ {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "--config":
			i++
			configIn = args[i]
		case "--output":
			i++
			configOut = args[i]
		case "--credentials-in":
			i++
			credentialsIn = args[i]
		case "--credentials-out":
			i++
			credentialsOut = args[i]
		case "--meta":
			i++
			metaPath = args[i]
		case "--mode":
			i++
			mode = args[i]
		case "--panel-url":
			i++
			panelURL = args[i]
		case "--node-id":
			i++
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return fmt.Errorf("invalid --node-id: %w", err)
			}
			nodeID = v
		case "--node-type":
			i++
			nodeType = args[i]
		case "--machine-id":
			i++
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return fmt.Errorf("invalid --machine-id: %w", err)
			}
			machineID = v
		case "--health-port":
			i++
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return fmt.Errorf("invalid --health-port: %w", err)
			}
			healthPort = v
		case "--gomemlimit":
			i++
			gomemlimit = args[i]
		case "--gogc":
			i++
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return fmt.Errorf("invalid --gogc: %w", err)
			}
			gogc = v
		case "--install-root":
			i++
			installRoot = args[i]
		case "--token":
			i++
			token = args[i]
		case "--version":
			i++
			releaseVersion = args[i]
		}
	}

	if mode == "" {
		return errors.New("--mode is required (node or machine)")
	}
	if panelURL == "" {
		return errors.New("--panel-url is required")
	}
	if mode == "node" && nodeID <= 0 {
		return errors.New("--node-id is required for node mode")
	}
	if mode == "machine" && machineID <= 0 {
		return errors.New("--machine-id is required for machine mode")
	}

	// Build the new instance.
	inst := config.Config{
		Panel: config.PanelConfig{URL: panelURL},
		Kernel: config.KernelConfig{
			LogLevel: "warn",
		},
		Log:        config.LogConfig{Level: "info", Output: "stdout"},
		HealthPort: healthPort,
	}

	if mode == "machine" {
		inst.Machine = &config.MachineConfig{MachineID: machineID}
	} else {
		inst.Panel.NodeID = nodeID
		if nodeType != "" {
			inst.Panel.NodeType = nodeType
		}
	}

	// Generate deterministic instance ID.
	instanceID, err := inst.AutoInstanceID()
	if err != nil {
		return fmt.Errorf("generate instance ID: %w", err)
	}
	inst.InstanceID = instanceID

	if installRoot == "" {
		installRoot = "/etc/xboard-node"
	}
	inst.Kernel.ConfigDir = filepath.Join(installRoot, "instances", instanceID)

	// Build credential env key.
	envKey := "INSTANCE_" + strings.ToUpper(strings.ReplaceAll(instanceID, "-", "_"))
	if mode == "machine" {
		envKey += "_MACHINE_TOKEN"
		inst.Machine.TokenEnv = envKey
	} else {
		envKey += "_API_KEY"
		inst.Panel.TokenEnv = envKey
	}

	if gomemlimit != "" {
		inst.Runtime.GoMemLimit = gomemlimit
	}
	if gogc > 0 {
		inst.Runtime.GoGCPercent = gogc
	}

	// Load existing config (if any).
	root := &config.RootConfig{}
	hasExisting := false
	if configIn != "" {
		if loaded, loadErr := loadWritableRootConfig(configIn); loadErr == nil {
			root = loaded
			hasExisting = len(root.Instances) > 0 || root.Config.Panel.URL != ""
		}
	}

	// Normalise existing instance IDs so dedup works correctly.
	var instances []config.Config
	if hasExisting {
		instances = normalizeRootInstances(root)
		seen := make(map[string]bool)
		deduped := make([]config.Config, 0, len(instances))
		for _, existing := range instances {
			autoID, idErr := existing.AutoInstanceID()
			if idErr == nil && autoID != "" {
				existing.InstanceID = autoID
			}
			id := existing.InstanceID
			if id != "" && seen[id] {
				continue
			}
			if id != "" {
				seen[id] = true
			}
			deduped = append(deduped, existing)
		}
		instances = deduped
	}

	// Merge: replace if same ID exists, otherwise append.
	replaced := false
	for i, existing := range instances {
		if existing.InstanceID == instanceID {
			instances[i] = inst
			replaced = true
			break
		}
	}
	if !replaced {
		instances = append(instances, inst)
	}
	root.Instances = instances

	// Write config.
	if configOut == "" {
		configOut = configIn
	}
	if configOut == "" {
		return errors.New("--output (or --config) is required")
	}
	if err := writeRootConfig(configOut, root); err != nil {
		return err
	}

	// Write credentials.
	if token != "" && credentialsOut != "" {
		if err := mergeCredentials(credentialsIn, credentialsOut, envKey, token); err != nil {
			return err
		}
	}

	// Write install-meta.json.
	if metaPath != "" {
		if err := writeInstallMetaVersioned(metaPath, root, releaseVersion, instanceID); err != nil {
			return err
		}
	}

	// Output for bash capture.
	fmt.Printf("INSTANCE_ID=%s\n", instanceID)
	fmt.Printf("ENV_KEY=%s\n", envKey)
	return nil
}

// mergeCredentials reads existing key=value credentials, adds/replaces
// the given key, and writes the result preserving insertion order.
func mergeCredentials(srcPath, dstPath, key, value string) error {
	entries := make(map[string]string)
	var order []string
	if srcPath != "" {
		data, err := os.ReadFile(srcPath)
		if err == nil {
			for _, raw := range strings.Split(string(data), "\n") {
				line := strings.TrimSpace(raw)
				if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
					continue
				}
				k, v, _ := strings.Cut(line, "=")
				if _, exists := entries[k]; !exists {
					order = append(order, k)
				}
				entries[k] = v
			}
		}
	}
	if _, exists := entries[key]; !exists {
		order = append(order, key)
	}
	entries[key] = value

	var buf strings.Builder
	for _, k := range order {
		fmt.Fprintf(&buf, "%s=%s\n", k, entries[k])
	}
	return os.WriteFile(dstPath, []byte(buf.String()), 0o600)
}

// writeInstallMetaVersioned writes install-meta.json with an explicit
// version and latest-instance-ID. When latestID is empty, the last
// instance in the config is used (backward compat with writeInstallMeta).
func writeInstallMetaVersioned(path string, root *config.RootConfig, ver, latestID string) error {
	if ver == "" {
		ver = "unknown"
	}
	instances := normalizeRootInstances(root)
	items := make([]instanceSummary, 0, len(instances))
	for _, inst := range instances {
		id, err := inst.AutoInstanceID()
		if err != nil {
			return err
		}
		if latestID == "" {
			latestID = id
		}
		item := instanceSummary{
			ID:         id,
			PanelURL:   inst.Panel.URL,
			Mode:       instanceMode(inst),
			NodeID:     intPtr(inst.Panel.NodeID),
			MachineID:  machineIDPtr(&inst),
			HealthPort: inst.HealthPort,
		}
		if item.Mode == "machine" {
			item.NodeID = nil
		}
		items = append(items, item)
	}
	meta := installMeta{
		ConfigMode:       "instances",
		Version:          ver,
		LatestInstanceID: latestID,
		InstanceCount:    len(items),
		Instances:        items,
		UpdatedAt:        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal install meta: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

// runConfigHealthPort reads health_port from an existing config file and
// prints it to stdout. Exits silently if the file does not exist or has
// no health_port.
func runConfigHealthPort(args []string) error {
	cfgPath := defaultConfigPath
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			i++
			cfgPath = args[i]
		}
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil // file not found → no health port
	}
	root := &config.RootConfig{}
	if err := yaml.Unmarshal(data, root); err != nil {
		return nil
	}
	// Check instances first, then legacy top-level.
	if len(root.Instances) > 0 {
		for _, inst := range root.Instances {
			if inst.HealthPort > 0 {
				fmt.Println(inst.HealthPort)
				return nil
			}
		}
	}
	if root.Config.HealthPort > 0 {
		fmt.Println(root.Config.HealthPort)
	}
	return nil
}
