package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type LogEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	Environment string                 `json:"environment"`
	Level       string                 `json:"level"`
	Message     string                 `json:"message"`
	Context     map[string]interface{} `json:"context,omitempty"`
	File        string                 `json:"file,omitempty"`
	Line        string                 `json:"line,omitempty"`
	StackTrace  string                 `json:"stack_trace,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
}

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[37m"
	ColorBold   = "\033[1m"
	ColorDim    = "\033[2m"
)

var (
	levelFilter = flag.String("level", "", "Filter by log level (DEBUG, INFO, WARNING, ERROR)")
	errorsOnly  = flag.Bool("errors-only", false, "Show only errors and warnings")
	groupBy     = flag.String("group-by", "", "Group results by: message, level, file, user")
	outputJSON  = flag.Bool("json", false, "Output in JSON format")
	summary     = flag.Bool("summary", false, "Show summary statistics")
	since       = flag.String("since", "", "Show logs since date (YYYY-MM-DD or YYYY-MM-DD HH:MM)")
	until       = flag.String("until", "", "Show logs until date (YYYY-MM-DD or YYYY-MM-DD HH:MM)")
	search      = flag.String("search", "", "Search for specific text in messages")
	userID      = flag.String("user", "", "Filter by user ID")
	noColor     = flag.Bool("no-color", false, "Disable colored output")
	compact     = flag.Bool("compact", false, "Compact output format")
	stats       = flag.Bool("stats", false, "Show detailed statistics")
	// follow      = flag.Bool("follow", false, "Follow log file for new entries")
	lastN      = flag.Int("last", 0, "Show last N entries")
	remotePath = flag.String("remote-path", "storage/logs/laravel.log", "Remote log file path")
	sshConfig  = flag.String("ssh-config", "", "Path to SSH config file (default: ~/.ssh/config)")
)

func main() {
	flag.Parse()

	if flag.NArg() < 1 {
		printUsage()
		os.Exit(1)
	}

	target := flag.Arg(0)

	var entries []LogEntry
	var err error

	if isRemoteTarget(target) {
		fmt.Printf("%s%sConnecting to %s...%s\n", ColorDim, ColorCyan, target, ColorReset)
		entries, err = parseRemoteLogFile(target)
	} else {
		entries, err = parseLogFile(target)
	}

	if err != nil {
		log.Fatal(err)
	}

	entries = filterEntries(entries)

	if *lastN > 0 && len(entries) > *lastN {
		entries = entries[len(entries)-*lastN:]
	}

	if *summary || *stats {
		showDetailedSummary(entries)
	} else if *groupBy != "" {
		showGrouped(entries)
	} else if *outputJSON {
		outputJSONEntries(entries)
	} else {
		showEntries(entries)
	}
}

func printUsage() {
	fmt.Printf("%s%sLaravel Log Parser%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Println("A powerful CLI tool for analyzing Laravel application logs")
	fmt.Println()
	fmt.Printf("%sUsage:%s parse [options] <logfile|ssh-host>\n", ColorBold, ColorReset)
	fmt.Println()
	fmt.Printf("%sExamples:%s\n", ColorBold, ColorReset)
	fmt.Println("  parse storage/logs/laravel.log")
	fmt.Println("  parse stage-web                    # SSH to stage-web and parse remote log")
	fmt.Println("  parse --errors-only stage-api")
	fmt.Println("  parse --summary --since=2025-06-13 production")
	fmt.Println("  parse --search=\"database\" --user=123 laravel.log")
	fmt.Println()
	fmt.Printf("%sSSH Remote Logs:%s\n", ColorBold, ColorReset)
	fmt.Println("  If the target looks like an SSH host, it will:")
	fmt.Println("  1. Look up the host in your ~/.ssh/config")
	fmt.Println("  2. SSH to that host and fetch the log file")
	fmt.Println("  3. Parse it locally with all the same features")
	fmt.Println()
	fmt.Printf("%sOptions:%s\n", ColorBold, ColorReset)
	flag.PrintDefaults()
}

func isRemoteTarget(target string) bool {
	if strings.Contains(target, "/") || strings.HasSuffix(target, ".log") {
		return false
	}

	if _, err := os.Stat(target); err == nil {
		return false
	}

	return true
}

func parseRemoteLogFile(host string) ([]LogEntry, error) {
	configPath := *sshConfig
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("could not find home directory: %v", err)
		}
		configPath = filepath.Join(home, ".ssh", "config")
	}

	sshHost, err := getSSHHostFromConfig(configPath, host)
	if err != nil {
		return nil, fmt.Errorf("SSH config error: %v", err)
	}

	cmd := exec.Command("ssh", sshHost, "cat", *remotePath)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start SSH command: %v", err)
	}

	entries, parseErr := parseLogReader(stdout)

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("SSH command failed: %v", err)
	}

	return entries, parseErr
}

func getSSHHostFromConfig(configPath, hostAlias string) (string, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return hostAlias, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inHostSection := false
	var hostname, user string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "Host ") {
			hosts := strings.Fields(line)[1:]
			inHostSection = false
			for _, h := range hosts {
				if h == hostAlias {
					inHostSection = true
					break
				}
			}
			continue
		}

		if !inHostSection {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := parts[1]

		switch key {
		case "hostname":
			hostname = value
		case "user":
			user = value
		}
	}

	if hostname == "" {
		hostname = hostAlias
	}

	sshTarget := hostname
	if user != "" {
		sshTarget = user + "@" + hostname
	}

	return sshTarget, nil
}

func parseLogFile(filename string) ([]LogEntry, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseLogReader(file)
}

func parseLogReader(reader io.Reader) ([]LogEntry, error) {
	var entries []LogEntry
	scanner := bufio.NewScanner(reader)

	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	logPattern := regexp.MustCompile(`^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (\w+)\.(\w+): (.+)$`)
	contextPattern := regexp.MustCompile(`^(.+?) (\{.+\})$`)

	for scanner.Scan() {
		line := scanner.Text()

		if matches := logPattern.FindStringSubmatch(line); matches != nil {
			timestamp, _ := time.Parse("2006-01-02 15:04:05", matches[1])

			entry := LogEntry{
				Timestamp:   timestamp,
				Environment: matches[2],
				Level:       matches[3],
				Message:     matches[4],
				Context:     make(map[string]interface{}),
			}

			if contextMatches := contextPattern.FindStringSubmatch(entry.Message); contextMatches != nil {
				entry.Message = strings.TrimSpace(contextMatches[1])

				var context map[string]interface{}
				if err := json.Unmarshal([]byte(contextMatches[2]), &context); err == nil {
					entry.Context = context
					extractContextData(&entry)
				}
			}

			parseStackTrace(&entry)
			entries = append(entries, entry)
		}
	}

	return entries, scanner.Err()
}

func extractContextData(entry *LogEntry) {
	if userID, ok := entry.Context["userId"]; ok {
		if uid, ok := userID.(float64); ok {
			entry.UserID = strconv.Itoa(int(uid))
		} else if uid, ok := userID.(string); ok {
			entry.UserID = uid
		}
	}

	if requestID, ok := entry.Context["request_id"].(string); ok {
		entry.RequestID = requestID
	}
}

func parseStackTrace(entry *LogEntry) {
	if strings.Contains(entry.Message, " in ") && strings.Contains(entry.Message, ":") {
		parts := strings.Split(entry.Message, " in ")
		if len(parts) >= 2 {
			entry.Message = strings.TrimSpace(parts[0])

			fileLine := strings.TrimSpace(parts[1])
			if idx := strings.LastIndex(fileLine, ":"); idx != -1 {
				entry.File = fileLine[:idx]
				entry.Line = fileLine[idx+1:]
			}
		}
	}
}

func filterEntries(entries []LogEntry) []LogEntry {
	var filtered []LogEntry

	var sinceTime, untilTime time.Time
	var err error

	if *since != "" {
		if strings.Contains(*since, " ") {
			sinceTime, err = time.Parse("2006-01-02 15:04", *since)
		} else {
			sinceTime, err = time.Parse("2006-01-02", *since)
		}
		if err != nil {
			log.Printf("Warning: invalid since date format: %v", err)
		}
	}

	if *until != "" {
		if strings.Contains(*until, " ") {
			untilTime, err = time.Parse("2006-01-02 15:04", *until)
		} else {
			untilTime, err = time.Parse("2006-01-02", *until)
			if err == nil {
				untilTime = untilTime.Add(24 * time.Hour)
			}
		}
		if err != nil {
			log.Printf("Warning: invalid until date format: %v", err)
		}
	}

	for _, entry := range entries {
		if *levelFilter != "" && entry.Level != strings.ToUpper(*levelFilter) {
			continue
		}

		if *errorsOnly && entry.Level != "ERROR" && entry.Level != "WARNING" {
			continue
		}

		if !sinceTime.IsZero() && entry.Timestamp.Before(sinceTime) {
			continue
		}

		if !untilTime.IsZero() && entry.Timestamp.After(untilTime) {
			continue
		}

		if *search != "" && !strings.Contains(strings.ToLower(entry.Message), strings.ToLower(*search)) {
			continue
		}

		if *userID != "" && entry.UserID != *userID {
			continue
		}

		filtered = append(filtered, entry)
	}

	return filtered
}

func getLevelColor(level string) string {
	if *noColor {
		return ""
	}
	switch level {
	case "ERROR":
		return ColorRed + ColorBold
	case "WARNING":
		return ColorYellow + ColorBold
	case "INFO":
		return ColorGreen
	case "DEBUG":
		return ColorGray
	default:
		return ColorBlue
	}
}

func getTimeColor() string {
	if *noColor {
		return ""
	}
	return ColorDim
}

func getFileColor() string {
	if *noColor {
		return ""
	}
	return ColorCyan
}

func showEntries(entries []LogEntry) {
	if len(entries) == 0 {
		fmt.Printf("%s%sNo log entries found matching your criteria.%s\n", ColorYellow, ColorBold, ColorReset)
		return
	}

	for _, entry := range entries {
		if *compact {
			showCompactEntry(entry)
		} else {
			showDetailedEntry(entry)
		}
	}

	if !*noColor {
		fmt.Printf("\n%s%s%d entries found%s\n", ColorDim, ColorBold, len(entries), ColorReset)
	} else {
		fmt.Printf("\n%d entries found\n", len(entries))
	}
}

func showCompactEntry(entry LogEntry) {
	timeColor := getTimeColor()
	levelColor := getLevelColor(entry.Level)
	fileColor := getFileColor()

	fmt.Printf("%s%s%s %s%-7s%s %s",
		timeColor, entry.Timestamp.Format("15:04:05"), ColorReset,
		levelColor, entry.Level, ColorReset,
		entry.Message)

	if entry.UserID != "" {
		fmt.Printf(" %s[user:%s]%s", ColorBlue, entry.UserID, ColorReset)
	}

	if entry.File != "" {
		fmt.Printf(" %s%s:%s%s", fileColor, getShortPath(entry.File), entry.Line, ColorReset)
	}

	fmt.Println()
}

func showDetailedEntry(entry LogEntry) {
	levelColor := getLevelColor(entry.Level)
	fileColor := getFileColor()

	fmt.Printf("%s╭─ %s %s[%s]%s %s%s%s\n",
		ColorDim,
		entry.Timestamp.Format("2006-01-02 15:04:05"),
		levelColor, entry.Level, ColorReset,
		ColorGray, entry.Environment, ColorReset)

	fmt.Printf("%s│  %s%s\n", ColorDim, ColorReset, entry.Message)

	if entry.UserID != "" || entry.RequestID != "" || entry.File != "" {
		fmt.Printf("%s│  ", ColorDim)

		if entry.UserID != "" {
			fmt.Printf("%sUser: %s%s  ", ColorBlue, entry.UserID, ColorReset)
		}

		if entry.RequestID != "" {
			fmt.Printf("%sRequest: %s%s  ", ColorPurple, entry.RequestID[:8], ColorReset)
		}

		if entry.File != "" {
			fmt.Printf("%sFile: %s:%s%s", fileColor, getShortPath(entry.File), entry.Line, ColorReset)
		}

		fmt.Println()
	}

	if len(entry.Context) > 0 {
		fmt.Printf("%s│  %sContext: %s", ColorDim, ColorGray, ColorReset)
		for key, value := range entry.Context {
			if key != "userId" && key != "request_id" {
				fmt.Printf("%s=%v ", key, value)
			}
		}
		fmt.Println()
	}

	fmt.Printf("%s╰─%s\n", ColorDim, ColorReset)
}

func getShortPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 3 {
		return ".../" + strings.Join(parts[len(parts)-2:], "/")
	}
	return path
}

func showDetailedSummary(entries []LogEntry) {
	if len(entries) == 0 {
		fmt.Printf("%s%sNo log entries found.%s\n", ColorYellow, ColorBold, ColorReset)
		return
	}

	levelCounts := make(map[string]int)
	errorMessages := make(map[string]int)
	hourlyStats := make(map[string]int)
	userStats := make(map[string]int)
	fileStats := make(map[string]int)

	for _, entry := range entries {
		levelCounts[entry.Level]++
		hourlyStats[entry.Timestamp.Format("15:00")]++

		if entry.Level == "ERROR" || entry.Level == "WARNING" {
			errorMessages[entry.Message]++
		}

		if entry.UserID != "" {
			userStats[entry.UserID]++
		}

		if entry.File != "" {
			fileStats[getShortPath(entry.File)]++
		}
	}

	fmt.Printf("%s%sLog Analysis Summary%s\n", ColorBold, ColorCyan, ColorReset)
	fmt.Printf("%s═══════════════════════%s\n", ColorCyan, ColorReset)
	fmt.Printf("Total entries: %s%d%s\n", ColorBold, len(entries), ColorReset)
	fmt.Printf("Time range: %s to %s\n",
		entries[0].Timestamp.Format("2006-01-02 15:04"),
		entries[len(entries)-1].Timestamp.Format("2006-01-02 15:04"))

	fmt.Printf("\n%sLog Levels:%s\n", ColorBold, ColorReset)
	for level, count := range levelCounts {
		color := getLevelColor(level)
		percentage := float64(count) / float64(len(entries)) * 100
		fmt.Printf("  %s%-8s%s %s%4d%s (%s%.1f%%%s)\n",
			color, level, ColorReset, ColorBold, count, ColorReset, ColorDim, percentage, ColorReset)
	}

	if len(errorMessages) > 0 {
		fmt.Printf("\n%sTop Issues:%s\n", ColorBold, ColorReset)

		type errorCount struct {
			message string
			count   int
		}

		var errors []errorCount
		for msg, count := range errorMessages {
			errors = append(errors, errorCount{msg, count})
		}

		sort.Slice(errors, func(i, j int) bool {
			return errors[i].count > errors[j].count
		})

		for i, err := range errors {
			if i >= 5 {
				break
			}
			fmt.Printf("  %s%d.%s %s (%s%d%s occurrences)\n",
				ColorRed, i+1, ColorReset, truncateString(err.message, 60), ColorBold, err.count, ColorReset)
		}
	}

	if *stats && len(userStats) > 0 {
		fmt.Printf("\n%sActive Users:%s\n", ColorBold, ColorReset)
		type userCount struct {
			userID string
			count  int
		}

		var users []userCount
		for uid, count := range userStats {
			users = append(users, userCount{uid, count})
		}

		sort.Slice(users, func(i, j int) bool {
			return users[i].count > users[j].count
		})

		for i, user := range users {
			if i >= 5 {
				break
			}
			fmt.Printf("  %sUser %s:%s %s%d%s events\n",
				ColorBlue, user.userID, ColorReset, ColorBold, user.count, ColorReset)
		}
	}

	if *stats && len(fileStats) > 0 {
		fmt.Printf("\n%s📁 Problem Files:%s\n", ColorBold, ColorReset)
		type fileCount struct {
			file  string
			count int
		}

		var files []fileCount
		for file, count := range fileStats {
			files = append(files, fileCount{file, count})
		}

		sort.Slice(files, func(i, j int) bool {
			return files[i].count > files[j].count
		})

		for i, file := range files {
			if i >= 5 {
				break
			}
			fmt.Printf("  %s%s:%s %s%d%s issues\n",
				getFileColor(), file.file, ColorReset, ColorBold, file.count, ColorReset)
		}
	}
}

func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}

func showGrouped(entries []LogEntry) {
	groups := make(map[string][]LogEntry)

	for _, entry := range entries {
		var key string
		switch *groupBy {
		case "level":
			key = entry.Level
		case "message":
			key = truncateString(entry.Message, 50)
		case "file":
			key = getShortPath(entry.File)
		case "user":
			key = entry.UserID
			if key == "" {
				key = "anonymous"
			}
		default:
			key = "unknown"
		}
		groups[key] = append(groups[key], entry)
	}

	type groupInfo struct {
		key     string
		entries []LogEntry
	}

	var sortedGroups []groupInfo
	for key, entries := range groups {
		sortedGroups = append(sortedGroups, groupInfo{key, entries})
	}

	sort.Slice(sortedGroups, func(i, j int) bool {
		return len(sortedGroups[i].entries) > len(sortedGroups[j].entries)
	})

	for _, group := range sortedGroups {
		color := ColorCyan
		if *groupBy == "level" {
			color = getLevelColor(group.key)
		}

		fmt.Printf("\n%s%s━━━ %s (%d entries) ━━━%s\n",
			ColorBold, color, group.key, len(group.entries), ColorReset)

		for i, entry := range group.entries {
			if i >= 3 {
				fmt.Printf("  %s... and %d more%s\n", ColorDim, len(group.entries)-3, ColorReset)
				break
			}
			fmt.Printf("  %s[%s]%s %s\n",
				getTimeColor(), entry.Timestamp.Format("15:04:05"), ColorReset,
				truncateString(entry.Message, 80))
		}
	}
}

func outputJSONEntries(entries []LogEntry) {
	output, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(output))
}
