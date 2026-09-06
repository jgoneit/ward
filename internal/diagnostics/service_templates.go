package diagnostics

import (
	"bytes"
	"encoding/xml"
	"io"
	"sort"
	"strconv"
	"strings"
)

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func launchAgentDefinition(d serviceDefinition) []byte {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>" + xmlText(d.ID) + "</string>\n<key>ProgramArguments</key><array>")
	for _, arg := range append([]string{d.Binary}, d.Args...) {
		b.WriteString("<string>" + xmlText(arg) + "</string>")
	}
	b.WriteString("</array>\n<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>5</integer>\n<key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string>\n</dict></plist>\n")
	return []byte(b.String())
}

func launchdMatches(data []byte, d serviceDefinition) bool {
	var program string
	var args []string
	inside := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "program = ") {
			program = strings.TrimPrefix(line, "program = ")
		}
		if line == "arguments = {" {
			inside = true
			continue
		}
		if inside {
			if line == "}" {
				inside = false
				continue
			}
			args = append(args, line)
		}
	}
	if program != d.Binary || len(args) != len(d.Args)+1 || args[0] != d.Binary {
		return false
	}
	for i, arg := range d.Args {
		if args[i+1] != arg {
			return false
		}
	}
	return true
}

func systemdArgument(value string) string {
	// systemd has its own argument parser, percent specifiers and dollar
	// expansion; shell quoting alone is insufficient.
	value = strings.ReplaceAll(value, "%", "%%")
	value = strings.ReplaceAll(value, "$", "$$")
	return strconv.Quote(value)
}

func systemdDefinition(d serviceDefinition) []byte {
	args := []string{systemdArgument(d.Binary)}
	for _, arg := range d.Args {
		args = append(args, systemdArgument(arg))
	}
	return []byte("[Unit]\nDescription=Ward local diagnostics collector\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nExecStart=" + strings.Join(args, " ") + "\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=5\nUMask=0077\nStandardOutput=null\nStandardError=null\n\n[Install]\nWantedBy=default.target\n")
}

func windowsArgument(arg string) string {
	if arg != "" && !strings.ContainsAny(arg, " \t\n\v\"") {
		return arg
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, r := range arg {
		if r == '\\' {
			slashes++
			continue
		}
		if r == '"' {
			b.WriteString(strings.Repeat("\\", slashes*2+1))
		} else {
			b.WriteString(strings.Repeat("\\", slashes))
		}
		slashes = 0
		b.WriteRune(r)
	}
	b.WriteString(strings.Repeat("\\", slashes*2))
	b.WriteByte('"')
	return b.String()
}

func scheduledTaskDefinition(d serviceDefinition) []byte {
	args := make([]string, len(d.Args))
	for i, arg := range d.Args {
		args[i] = windowsArgument(arg)
	}
	// A registration trigger starts recovery checks immediately after enable;
	// the user logon trigger resumes them for each later interactive session.
	// IgnoreNew keeps each check from replacing an already running collector.
	repetition := `<Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>`
	// RegisterTask receives a Unicode BSTR, independent of the UTF-8 JSON
	// transport. Do not declare a byte encoding for that COM string.
	return []byte(`<?xml version="1.0"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Description>Ward local diagnostics collector</Description></RegistrationInfo>
<Triggers><LogonTrigger><Enabled>true</Enabled>` + repetition + `<UserId>` + xmlText(d.UserID) + `</UserId></LogonTrigger><RegistrationTrigger><Enabled>true</Enabled>` + repetition + `<Delay>PT1M</Delay></RegistrationTrigger></Triggers>
<Principals><Principal id="CurrentUser"><UserId>` + xmlText(d.UserID) + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority><RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure></Settings>
<Actions Context="CurrentUser"><Exec><Command>` + xmlText(d.Binary) + `</Command><Arguments>` + xmlText(strings.Join(args, " ")) + `</Arguments></Exec></Actions>
</Task>`)
}

// Task Scheduler also omits these exact schema defaults when exporting a task.
// Only leaf nodes at their schema location can be equivalent to omission.
var scheduledTaskDefaults = map[string]string{
	"Task/Principals/Principal/RunLevel":                             "LeastPrivilege",
	"Task/Triggers/LogonTrigger/Enabled":                             "true",
	"Task/Triggers/RegistrationTrigger/Enabled":                      "true",
	"Task/Triggers/LogonTrigger/Repetition/StopAtDurationEnd":        "false",
	"Task/Triggers/RegistrationTrigger/Repetition/StopAtDurationEnd": "false",
	"Task/Settings/AllowHardTerminate":                               "true",
	"Task/Settings/StartWhenAvailable":                               "false",
	"Task/Settings/RunOnlyIfNetworkAvailable":                        "false",
	"Task/Settings/AllowStartOnDemand":                               "true",
	"Task/Settings/Hidden":                                           "false",
	"Task/Settings/RunOnlyIfIdle":                                    "false",
	"Task/Settings/WakeToRun":                                        "false",
	"Task/Settings/Priority":                                         "7",
}

// Task Scheduler normalizes whitespace, element order, the root version,
// registration metadata and default-valued settings. Non-default execution or
// security settings, extra actions, triggers and unknown settings still fail.
func canonicalTaskXML(data []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	// COM already decoded task XML into a Unicode string; PowerShell JSON
	// transports it as UTF-8 even when its declaration still says UTF-16.
	decoder.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
		if strings.EqualFold(label, "utf-16") {
			return input, nil
		}
		return nil, io.ErrUnexpectedEOF
	}
	const taskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task"
	normalizedPaths := make(map[string]bool)
	var walk func(xml.StartElement, string) (string, error)
	walk = func(start xml.StartElement, parent string) (string, error) {
		if start.Name.Space != taskNamespace {
			return "", io.ErrUnexpectedEOF
		}
		name := start.Name.Local
		path := name
		if parent != "" {
			path = parent + "/" + name
		}
		var children []string
		hasChildren := false
		var text strings.Builder
		for {
			token, err := decoder.Token()
			if err != nil {
				return "", err
			}
			switch t := token.(type) {
			case xml.StartElement:
				hasChildren = true
				child, err := walk(t, path)
				if err != nil {
					return "", err
				}
				if child != "" {
					children = append(children, child)
				}
			case xml.CharData:
				text.Write(t)
			case xml.EndElement:
				sort.Strings(children)
				attrs := []string{}
				for _, a := range start.Attr {
					if (a.Name.Space == "" && a.Name.Local == "xmlns") || a.Name.Space == "xmlns" || (path == "Task" && a.Name.Space == "" && a.Name.Local == "version") {
						continue
					}
					attrs = append(attrs, "{"+a.Name.Space+"}"+a.Name.Local+"="+a.Value)
				}
				sort.Strings(attrs)
				value := text.String()
				defaultValue, hasDefault := scheduledTaskDefaults[path]
				mutableEnabled := path == "Task/Settings/Enabled"
				metadata := parent == "Task/RegistrationInfo" && (name == "URI" || name == "Author" || name == "Date")
				if hasDefault || mutableEnabled || metadata {
					if normalizedPaths[path] {
						return "", io.ErrUnexpectedEOF
					}
					normalizedPaths[path] = true
					if !hasChildren && len(attrs) == 0 && (metadata || (hasDefault && value == defaultValue) || (mutableEnabled && (value == "true" || value == "false"))) {
						return "", nil
					}
				}
				if len(children) > 0 || strings.TrimSpace(value) == "" {
					value = strings.TrimSpace(value)
				}
				return name + "[" + strings.Join(attrs, ",") + "]{" + value + strings.Join(children, "") + "}", nil
			}
		}
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", err
		}
		if start, ok := token.(xml.StartElement); ok {
			if start.Name.Local != "Task" {
				return "", io.ErrUnexpectedEOF
			}
			value, err := walk(start, "")
			if err != nil {
				return "", err
			}
			for {
				token, err := decoder.Token()
				if err == io.EOF {
					return value, nil
				}
				if err != nil {
					return "", err
				}
				if chars, ok := token.(xml.CharData); !ok || strings.TrimSpace(string(chars)) != "" {
					return "", io.ErrUnexpectedEOF
				}
			}
		}
	}
}

func scheduledTaskMatches(actual, expected []byte) bool {
	a, err := canonicalTaskXML(actual)
	if err != nil {
		return false
	}
	b, err := canonicalTaskXML(expected)
	return err == nil && a == b
}
