package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	defaultDialTimeout = 1 * time.Second
	defaultReadTimeout = 2 * time.Second
)

type scanResult struct {
	Port   int    `json:"port"`
	Open   bool   `json:"open"`
	Banner string `json:"banner,omitempty"`
}

type jsonReport struct {
	Host      string       `json:"host"`
	StartPort int          `json:"start_port"`
	EndPort   int          `json:"end_port"`
	Workers   int          `json:"workers"`
	ScannedAt time.Time    `json:"scanned_at"`
	Duration  string       `json:"duration"`
	OpenPorts []scanResult `json:"open_ports"`
}

type progressMsg struct {
	Completed int
	Total     int
}

type foundPortMsg struct {
	Result scanResult
}

type completeMsg struct {
	Duration time.Duration
	JSONPath string
	JSONErr  error
}

type model struct {
	host      string
	startPort int
	endPort   int
	workers   int

	events <-chan tea.Msg

	progressBar progress.Model
	completed   int
	total       int
	openPorts   []scanResult
	duration    time.Duration
	done        bool
	jsonPath    string
	jsonErr     error
	quitting    bool
}

var (
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Padding(0, 1)
	panelStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("63")).Padding(1, 2)
	mutedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	goodStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
)

func initialModel(host string, startPort int, endPort int, workers int, events <-chan tea.Msg) model {
	total := endPort - startPort + 1
	bar := progress.New(progress.WithDefaultGradient(), progress.WithWidth(48))

	return model{
		host:        host,
		startPort:   startPort,
		endPort:     endPort,
		workers:     workers,
		events:      events,
		progressBar: bar,
		total:       total,
		openPorts:   make([]scanResult, 0, 16),
	}
}

func waitForScannerEvent(events <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-events
		if !ok {
			return completeMsg{}
		}
		return msg
	}
}

func (m model) Init() tea.Cmd {
	return waitForScannerEvent(m.events)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch strings.ToLower(msg.String()) {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.progressBar.Width = max(16, msg.Width-24)

	case progressMsg:
		m.completed = msg.Completed
		m.total = msg.Total
		pct := 0.0
		if m.total > 0 {
			pct = float64(m.completed) / float64(m.total)
		}
		barCmd := m.progressBar.SetPercent(pct)
		if m.done {
			return m, barCmd
		}
		return m, tea.Batch(barCmd, waitForScannerEvent(m.events))

	case foundPortMsg:
		m.openPorts = append(m.openPorts, msg.Result)
		if m.done {
			return m, nil
		}
		return m, waitForScannerEvent(m.events)

	case completeMsg:
		m.done = true
		m.duration = msg.Duration
		m.jsonPath = msg.JSONPath
		m.jsonErr = msg.JSONErr
		return m, nil

	case progress.FrameMsg:
		updated, cmd := m.progressBar.Update(msg)
		m.progressBar = updated.(progress.Model)
		return m, cmd
	}

	if m.done {
		return m, nil
	}
	return m, waitForScannerEvent(m.events)
}

func (m model) View() string {
	if m.quitting {
		return "\nGoodbye.\n"
	}

	header := headerStyle.Render("🚀 Gopher Port Scanner")
	meta := mutedStyle.Render(fmt.Sprintf("Target: %s | Range: %d-%d | Workers: %d", m.host, m.startPort, m.endPort, m.workers))

	pct := 0.0
	if m.total > 0 {
		pct = float64(m.completed) / float64(m.total)
	}
	progressLine := fmt.Sprintf("%s  %.1f%% (%d/%d)", m.progressBar.View(), pct*100, m.completed, m.total)

	openHeader := goodStyle.Render(fmt.Sprintf("Open Ports Found: %d", len(m.openPorts)))
	openRows := m.lastTenOpenRows()

	status := mutedStyle.Render("Scanning in progress...")
	if m.done {
		status = goodStyle.Render(fmt.Sprintf("Scan complete in %s", m.duration.Round(time.Millisecond)))
		if m.jsonPath != "" && m.jsonErr == nil {
			status += "\n" + goodStyle.Render("Saved JSON report: "+m.jsonPath)
		}
		if m.jsonErr != nil {
			status += "\n" + warnStyle.Render("JSON save failed: "+m.jsonErr.Error())
		}
	}

	footer := mutedStyle.Render("Press Q to quit")

	body := strings.Join([]string{
		header,
		meta,
		"",
		progressLine,
		"",
		openHeader,
		openRows,
		"",
		status,
		"",
		footer,
	}, "\n")

	return "\n" + panelStyle.Render(body) + "\n"
}

func (m model) lastTenOpenRows() string {
	if len(m.openPorts) == 0 {
		return mutedStyle.Render("No open ports discovered yet.")
	}

	start := 0
	if len(m.openPorts) > 10 {
		start = len(m.openPorts) - 10
	}

	var lines []string
	for _, item := range m.openPorts[start:] {
		banner := item.Banner
		if banner == "" {
			banner = "(none)"
		}
		if len(banner) > 100 {
			banner = banner[:100] + "..."
		}
		lines = append(lines, fmt.Sprintf("• %5d  %s", item.Port, banner))
	}

	return strings.Join(lines, "\n")
}

func formatHTTPBanner(response string) string {
	cleanResponse := strings.ReplaceAll(response, "\r\n", "\n")
	cleanResponse = strings.TrimSpace(cleanResponse)
	if cleanResponse == "" {
		return "(no http banner)"
	}

	lines := strings.Split(cleanResponse, "\n")
	parts := make([]string, 0, 4)

	if len(lines) > 0 {
		statusLine := strings.TrimSpace(lines[0])
		if strings.HasPrefix(strings.ToUpper(statusLine), "HTTP/") {
			parts = append(parts, statusLine)
		}
	}

	headers := map[string]string{}
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		sep := strings.Index(line, ":")
		if sep <= 0 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(line[:sep]))
		value := strings.TrimSpace(line[sep+1:])
		if key != "" && value != "" {
			headers[key] = value
		}
	}

	for _, key := range []string{"server", "x-powered-by", "via", "x-aspnet-version", "x-runtime"} {
		if val, ok := headers[key]; ok {
			parts = append(parts, fmt.Sprintf("%s: %s", key, val))
		}
	}

	if len(parts) > 0 {
		return strings.Join(parts, " | ")
	}

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if len(line) > 120 {
			line = line[:120] + "..."
		}
		return "raw: " + line
	}

	return "(no http banner)"
}

func isLikelyHTTPPort(port int) bool {
	httpPorts := []int{80, 81, 3000, 5000, 8000, 8080, 8081, 8888, 9000}
	return slices.Contains(httpPorts, port)
}

func readTCPBanner(conn net.Conn) string {
	_ = conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return "(none)"
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	if banner == "" {
		return "(none)"
	}
	return banner
}

func grabHTTPBanner(host string, port int) string {
	address := fmt.Sprintf("%s:%d", host, port)
	requests := []string{
		"HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: go-port-scanner/1.0\r\nConnection: close\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: go-port-scanner/1.0\r\nConnection: close\r\n\r\n",
	}

	for _, template := range requests {
		conn, err := net.DialTimeout("tcp", address, defaultDialTimeout)
		if err != nil {
			continue
		}

		_ = conn.SetWriteDeadline(time.Now().Add(defaultReadTimeout))
		request := fmt.Sprintf(template, host)
		_, writeErr := conn.Write([]byte(request))
		if writeErr != nil {
			_ = conn.Close()
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
		reader := bufio.NewReader(conn)
		buffer := make([]byte, 0, 4096)
		tmp := make([]byte, 1024)
		for len(buffer) < 4096 {
			n, readErr := reader.Read(tmp)
			if n > 0 {
				buffer = append(buffer, tmp[:n]...)
				if strings.Contains(string(buffer), "\r\n\r\n") {
					break
				}
			}
			if readErr != nil {
				break
			}
		}

		_ = conn.Close()

		if len(buffer) > 0 {
			banner := formatHTTPBanner(string(buffer))
			if banner != "(no http banner)" {
				return banner
			}
		}
	}

	return "(http open, banner unavailable)"
}

func ScanPort(host string, port int) scanResult {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, defaultDialTimeout)
	if err != nil {
		return scanResult{Port: port, Open: false}
	}
	_ = conn.Close()

	result := scanResult{Port: port, Open: true}
	if isLikelyHTTPPort(port) {
		result.Banner = grabHTTPBanner(host, port)
		return result
	}

	dataConn, err := net.DialTimeout("tcp", address, defaultDialTimeout)
	if err != nil {
		result.Banner = "(none)"
		return result
	}
	defer dataConn.Close()
	result.Banner = readTCPBanner(dataConn)
	return result
}

func worker(host string, jobs <-chan int, results chan<- scanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for port := range jobs {
		results <- ScanPort(host, port)
	}
}

func writeJSONReport(path string, report jsonReport) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func runScanner(host string, startPort int, endPort int, workers int, jsonFile string, events chan<- tea.Msg) {
	totalPorts := endPort - startPort + 1
	jobs := make(chan int, workers)
	results := make(chan scanResult, workers)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker(host, jobs, results, &wg)
	}

	startedAt := time.Now()

	go func() {
		for port := startPort; port <= endPort; port++ {
			jobs <- port
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	openPorts := make([]scanResult, 0, 16)
	completed := 0

	for res := range results {
		completed++
		events <- progressMsg{Completed: completed, Total: totalPorts}
		if res.Open {
			openPorts = append(openPorts, res)
			events <- foundPortMsg{Result: res}
		}
	}

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	duration := time.Since(startedAt)

	var jsonErr error
	if jsonFile != "" {
		report := jsonReport{
			Host:      host,
			StartPort: startPort,
			EndPort:   endPort,
			Workers:   workers,
			ScannedAt: startedAt,
			Duration:  duration.String(),
			OpenPorts: openPorts,
		}
		jsonErr = writeJSONReport(jsonFile, report)
	}

	events <- completeMsg{Duration: duration, JSONPath: jsonFile, JSONErr: jsonErr}
}

func main() {
	host := flag.String("host", "", "Target host or IP (required)")
	startPort := flag.Int("start", 1, "Start port")
	endPort := flag.Int("end", 1024, "End port")
	workers := flag.Int("workers", 50, "Number of worker goroutines")
	jsonFile := flag.String("json", "", "Optional path to save open-port results as JSON")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "error: -host is required")
		flag.Usage()
		os.Exit(1)
	}
	if *startPort < 1 || *endPort > 65535 || *startPort > *endPort {
		fmt.Fprintln(os.Stderr, "error: invalid port range, expected 1 <= start <= end <= 65535")
		os.Exit(1)
	}
	if *workers <= 0 {
		fmt.Fprintln(os.Stderr, "error: -workers must be greater than 0")
		os.Exit(1)
	}

	events := make(chan tea.Msg, 256)
	go runScanner(*host, *startPort, *endPort, *workers, *jsonFile, events)

	appModel := initialModel(*host, *startPort, *endPort, *workers, events)
	program := tea.NewProgram(appModel)
	if _, err := program.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to run TUI: %v\n", err)
		os.Exit(1)
	}
}
