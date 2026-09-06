package diagnostics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jgoneit/ward/internal/securefs"
)

var (
	ErrUnsupportedService = errors.New("diagnostics user service is unavailable")
	ErrServiceConflict    = errors.New("diagnostics service ownership conflict")
)

type serviceDefinition struct {
	Backend string
	ID      string
	Path    string
	Binary  string
	Args    []string
	Content []byte
	UserID  string
}

type serviceState struct{ Exists, Enabled, Running bool }

type serviceBackend interface {
	preflight(context.Context) error
	inspect(context.Context, serviceDefinition) (serviceState, error)
	install(context.Context, serviceDefinition) error
	start(context.Context, serviceDefinition) error
	stop(context.Context, serviceDefinition) error
	remove(context.Context, serviceDefinition) error
	restore(context.Context, serviceDefinition, serviceState) error
}

type commandRunner func(context.Context, string, []string, []byte) ([]byte, error)

type serviceCommandError struct{ code int }

func (e serviceCommandError) Error() string { return "diagnostics service command failed" }

func serviceCommandTimeout() time.Duration {
	if runtime.GOOS == "windows" {
		// Cold Windows PowerShell/COM startup can exceed five seconds.
		// This bounds management commands only, never the Hook sender.
		return 15 * time.Second
	}
	return 5 * time.Second
}

func runServiceCommand(ctx context.Context, program string, args []string, input []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, serviceCommandTimeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Stdin = bytes.NewReader(input)
	// Commands return only selected service metadata. Raw stderr may contain
	// user paths and environment values and never becomes a public error.
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return out, serviceCommandError{exit.ExitCode()}
		}
		return nil, ErrUnsupportedService
	}
	return out, nil
}

type nativeService struct {
	platform, userID string
	unitDir          string
	run              commandRunner
}

func newNativeService() (nativeService, error) {
	u, err := user.Current()
	if err != nil || u.Uid == "" {
		return nativeService{}, ErrUnsupportedService
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return nativeService{}, ErrUnsupportedService
	}
	return nativeService{platform: runtime.GOOS, userID: u.Uid, run: runServiceCommand}, nil
}

func collectorBinary(paths Paths, platform string) string {
	name := "ward-diagnostics"
	if platform == "windows" {
		name += ".exe"
	}
	return filepath.Join(filepath.Dir(paths.BinaryPath), name)
}

func makeServiceDefinition(paths Paths, platform, userID string, configHomes ...string) (serviceDefinition, error) {
	d := serviceDefinition{Binary: collectorBinary(paths, platform), UserID: userID,
		Args: []string{"diagnostics", "serve", "--core-dir", paths.CoreDir, "--home-dir", paths.HomeDir, "--binary-path", paths.BinaryPath}}
	identity := sha256.Sum256([]byte(userID + "\x00" + filepath.Clean(paths.BinaryPath)))
	suffix := hex.EncodeToString(identity[:12])
	switch platform {
	case "darwin":
		if _, err := strconv.ParseUint(userID, 10, 32); err != nil {
			return d, ErrUnsupportedService
		}
		d.Backend, d.ID = "launchd", "io.github.jgoneit.ward.diagnostics."+suffix
		d.Path = filepath.Join(paths.HomeDir, "Library", "LaunchAgents", d.ID+".plist")
		d.Content = launchAgentDefinition(d)
	case "linux":
		d.Backend, d.ID = "systemd-user", "ward-diagnostics-"+suffix+".service"
		configHome := filepath.Join(paths.HomeDir, ".config")
		if len(configHomes) > 0 && configHomes[0] != "" {
			if !filepath.IsAbs(configHomes[0]) {
				return d, ErrUnsupportedService
			}
			configHome = filepath.Clean(configHomes[0])
		}
		d.Path = filepath.Join(configHome, "systemd", "user", d.ID)
		d.Content = systemdDefinition(d)
	case "windows":
		if !strings.HasPrefix(userID, "S-1-") {
			return d, ErrUnsupportedService
		}
		d.Backend, d.ID = "windows-task", "WardDiagnostics-"+suffix
		d.Content = scheduledTaskDefinition(d)
	default:
		return d, ErrUnsupportedService
	}
	return d, nil
}

func (n nativeService) preflight(ctx context.Context) error {
	switch n.platform {
	case "darwin":
		_, err := n.run(ctx, "/bin/launchctl", []string{"print", "gui/" + n.userID}, nil)
		if err != nil {
			return ErrUnsupportedService
		}
	case "linux":
		_, err := n.run(ctx, "systemctl", []string{"--user", "show", "--property=Version", "--no-pager"}, nil)
		if err != nil {
			return ErrUnsupportedService
		}
		if n.unitDir != "" {
			if err := inspectParentChain(n.unitDir); err != nil {
				return ErrUnsupportedService
			}
			out, err := n.run(ctx, "busctl", []string{"--user", "--json=short", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "UnitPath"}, nil)
			if err != nil || !managerSearchesUnitDir(out, n.unitDir) {
				return ErrUnsupportedService
			}
		}
	case "windows":
		_, err := n.windows(ctx, "preflight", serviceDefinition{})
		if err != nil {
			return ErrUnsupportedService
		}
	default:
		return ErrUnsupportedService
	}
	return nil
}

func managerSearchesUnitDir(data []byte, expected string) bool {
	var property struct {
		Type string   `json:"type"`
		Data []string `json:"data"`
	}
	if json.Unmarshal(data, &property) != nil || property.Type != "as" {
		return false
	}
	for _, path := range property.Data {
		if filepath.Clean(path) == filepath.Clean(expected) {
			return true
		}
	}
	return false
}

func (n nativeService) inspect(ctx context.Context, d serviceDefinition) (serviceState, error) {
	var state serviceState
	if d.Path != "" {
		raw, err := readServiceDefinition(d.Path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return state, err
		}
		if err == nil {
			state.Exists = true
			if !bytes.Equal(raw, d.Content) {
				return state, ErrServiceConflict
			}
		}
	}
	switch n.platform {
	case "darwin":
		out, err := n.run(ctx, "/bin/launchctl", []string{"print", "gui/" + n.userID + "/" + d.ID}, nil)
		if err != nil {
			var commandErr serviceCommandError
			if errors.As(err, &commandErr) && commandErr.code == 113 {
				return state, nil
			}
			return state, err
		}
		if !state.Exists || !launchdMatches(out, d) {
			return state, ErrServiceConflict
		}
		state.Enabled = true
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "pid = ") {
				pid, err := strconv.Atoi(strings.TrimPrefix(line, "pid = "))
				state.Running = err == nil && pid > 0
			}
		}
	case "linux":
		out, err := n.run(ctx, "systemctl", []string{"--user", "show", d.ID, "--property=LoadState,ActiveState,SubState,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState,MainPID", "--no-pager"}, nil)
		fields := keyValues(out)
		if fields["LoadState"] == "not-found" {
			return state, nil
		}
		if err != nil {
			return state, err
		}
		if !state.Exists || fields["LoadState"] != "loaded" || fields["FragmentPath"] != d.Path || fields["DropInPaths"] != "" || fields["NeedDaemonReload"] != "no" {
			return state, ErrServiceConflict
		}
		state.Enabled = fields["UnitFileState"] == "enabled"
		pid, _ := strconv.Atoi(fields["MainPID"])
		state.Running = pid > 0 || fields["ActiveState"] == "active" || fields["ActiveState"] == "activating" || fields["ActiveState"] == "deactivating"
	case "windows":
		r, err := n.windows(ctx, "inspect", d)
		if err != nil {
			return state, err
		}
		state = serviceState{r.Exists, r.Enabled, r.Running}
		if r.Exists && !scheduledTaskMatches([]byte(r.XML), d.Content) {
			return state, ErrServiceConflict
		}
	}
	return state, nil
}

func (n nativeService) install(ctx context.Context, d serviceDefinition) error {
	if d.Path != "" {
		if err := ensureServiceParent(filepath.Dir(d.Path)); err != nil {
			return err
		}
		if err := writeOwnedArtifactAtomic(d.Path, d.Content, 0o600); err != nil {
			return err
		}
	}
	switch n.platform {
	case "darwin":
		_, err := n.run(ctx, "/bin/launchctl", []string{"bootstrap", "gui/" + n.userID, d.Path}, nil)
		return err
	case "linux":
		if _, err := n.run(ctx, "systemctl", []string{"--user", "daemon-reload"}, nil); err != nil {
			return err
		}
		_, err := n.run(ctx, "systemctl", []string{"--user", "enable", d.ID}, nil)
		return err
	case "windows":
		_, err := n.windows(ctx, "install", d)
		return err
	}
	return ErrUnsupportedService
}

func (n nativeService) start(ctx context.Context, d serviceDefinition) error {
	switch n.platform {
	case "darwin":
		_, err := n.run(ctx, "/bin/launchctl", []string{"kickstart", "gui/" + n.userID + "/" + d.ID}, nil)
		return err
	case "linux":
		_, err := n.run(ctx, "systemctl", []string{"--user", "start", d.ID}, nil)
		return err
	case "windows":
		_, err := n.windows(ctx, "start", d)
		return err
	}
	return ErrUnsupportedService
}

func (n nativeService) stop(ctx context.Context, d serviceDefinition) error {
	state, err := n.inspect(ctx, d)
	if err != nil {
		return err
	}
	if !state.Enabled && !state.Running {
		return nil
	}
	switch n.platform {
	case "darwin":
		_, err := n.run(ctx, "/bin/launchctl", []string{"bootout", "gui/" + n.userID + "/" + d.ID}, nil)
		var commandErr serviceCommandError
		if errors.As(err, &commandErr) && commandErr.code == 113 {
			return nil
		}
		return err
	case "linux":
		_, err := n.run(ctx, "systemctl", []string{"--user", "disable", "--now", d.ID}, nil)
		return err
	case "windows":
		_, err := n.windows(ctx, "stop", d)
		return err
	}
	return ErrUnsupportedService
}

func (n nativeService) restore(ctx context.Context, d serviceDefinition, previous serviceState) error {
	if !previous.Exists {
		return nil
	}
	if n.platform == "windows" {
		_, err := n.windowsRequest(ctx, windowsServiceRequest{Action: "restore", Name: d.ID, XML: string(d.Content), UserID: d.UserID, Enabled: previous.Enabled, Running: previous.Running})
		return err
	}
	if err := ensureServiceParent(filepath.Dir(d.Path)); err != nil {
		return err
	}
	if err := writeOwnedArtifactAtomic(d.Path, d.Content, 0o600); err != nil {
		return err
	}
	if n.platform == "darwin" {
		if previous.Enabled {
			_, err := n.run(ctx, "/bin/launchctl", []string{"bootstrap", "gui/" + n.userID, d.Path}, nil)
			return err
		}
		return nil
	}
	if _, err := n.run(ctx, "systemctl", []string{"--user", "daemon-reload"}, nil); err != nil {
		return err
	}
	if previous.Enabled {
		if _, err := n.run(ctx, "systemctl", []string{"--user", "enable", d.ID}, nil); err != nil {
			return err
		}
	}
	if previous.Running {
		return n.start(ctx, d)
	}
	return nil
}

func (n nativeService) remove(ctx context.Context, d serviceDefinition) error {
	if n.platform == "windows" {
		_, err := n.windows(ctx, "remove", d)
		return err
	}
	if raw, err := readServiceDefinition(d.Path); err == nil {
		if !bytes.Equal(raw, d.Content) {
			return ErrServiceConflict
		}
		if err := os.Remove(d.Path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if n.platform == "linux" {
		_, err := n.run(ctx, "systemctl", []string{"--user", "daemon-reload"}, nil)
		return err
	}
	return nil
}

func keyValues(data []byte) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			values[key] = value
		}
	}
	return values
}

func readServiceDefinition(path string) ([]byte, error) {
	if err := inspectRegularOwnedFile(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > 64*1024 {
		return nil, ErrServiceConflict
	}
	if err := securefs.InspectPrivateFile(path); err != nil {
		return nil, ErrServiceConflict
	}
	return os.ReadFile(path)
}

func ensureServiceParent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := ensureServiceParent(filepath.Dir(path)); err != nil {
			return err
		}
		return os.Mkdir(path, 0o700)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0) {
		return ErrServiceConflict
	}
	return nil
}

type windowsServiceReply struct {
	Exists, Enabled, Running bool
	XML                      string
}

type windowsServiceRequest struct {
	Action, Name, XML, UserID string
	Enabled, Running          bool
}

func (n nativeService) windows(ctx context.Context, action string, d serviceDefinition) (windowsServiceReply, error) {
	return n.windowsRequest(ctx, windowsServiceRequest{Action: action, Name: d.ID, XML: string(d.Content), UserID: d.UserID})
}

func (n nativeService) windowsRequest(ctx context.Context, request windowsServiceRequest) (windowsServiceReply, error) {
	var result windowsServiceReply
	input, _ := json.Marshal(request)
	program, err := servicePowerShellPath()
	if err != nil {
		return result, err
	}
	out, err := n.run(ctx, program, []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", windowsServiceScript}, input)
	if err != nil {
		return result, err
	}
	var reply struct {
		windowsServiceReply
		BackendHResult *int32
	}
	if err := json.Unmarshal(out, &reply); err != nil {
		return result, fmt.Errorf("diagnostics service response is invalid")
	}
	if reply.BackendHResult != nil {
		return result, fmt.Errorf("diagnostics service backend failed (hresult=0x%08x)", uint32(*reply.BackendHResult))
	}
	return reply.windowsServiceReply, nil
}

const windowsServiceScript = `$ErrorActionPreference='Stop'
$utf8=[System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding=$utf8
[Console]::OutputEncoding=$utf8
$OutputEncoding=$utf8
try {
$inputData=[Console]::In.ReadToEnd()|ConvertFrom-Json
$scheduler=New-Object -ComObject 'Schedule.Service'
$scheduler.Connect()
$folder=$scheduler.GetFolder('\')
if($inputData.Action -eq 'preflight'){ '{}'; exit 0 }
$task=$null
try { $task=$folder.GetTask($inputData.Name) } catch { if($_.Exception.GetBaseException().HResult -ne -2147024894){throw} }
switch($inputData.Action){
 'inspect' { if($null -eq $task){ '{"Exists":false}' }else{ @{Exists=$true;Enabled=$task.Enabled;Running=($task.State -eq 4 -or $task.State -eq 2);XML=$task.Xml}|ConvertTo-Json -Compress }; break }
 'install' { $null=$folder.RegisterTask($inputData.Name,$inputData.XML,6,$inputData.UserID,$null,3,$null); '{}'; break }
 'start' { if($null -eq $task){throw 'absent'}; $task.Enabled=$true; $null=$task.Run($null); '{}'; break }
 'stop' { if($null -ne $task){$task.Enabled=$false; $task.Stop(0)}; '{}'; break }
 'remove' { if($null -ne $task){$folder.DeleteTask($inputData.Name,0)}; '{}'; break }
 'restore' { $definition=$scheduler.NewTask(0); $definition.XmlText=$inputData.XML; $definition.Settings.Enabled=$inputData.Enabled; $restored=$folder.RegisterTaskDefinition($inputData.Name,$definition,6,$inputData.UserID,$null,3,$null); if($inputData.Running){$restored.Enabled=$true; $null=$restored.Run($null); $restored.Enabled=$inputData.Enabled}; '{}'; break }
 default { throw 'unsupported action' }
}
} catch {
 @{BackendHResult=[int]$_.Exception.GetBaseException().HResult}|ConvertTo-Json -Compress
 exit 0
}`
