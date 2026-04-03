package engine

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type Dashboard struct {
	Target      string
	StartTime   time.Time
	Progress    float64
	VulnCount   map[string]int
	CurrentTask string
	Assets      int
	Mu          sync.Mutex
	LastRender  time.Time
}

func NewDashboard(target string) *Dashboard {
	return &Dashboard{
		Target:    target,
		StartTime: time.Now(),
		VulnCount: make(map[string]int),
	}
}

func (d *Dashboard) Update(task string, progress float64, found int) {
	d.Mu.Lock()
	d.CurrentTask = task
	d.Progress = progress
	d.Assets = found
	d.Mu.Unlock()
	d.Render()
}

func (d *Dashboard) AddVuln(severity string) {
	d.Mu.Lock()
	d.VulnCount[severity]++
	d.Mu.Unlock()
	d.Render()
}

func (d *Dashboard) Render() {
	d.Mu.Lock()
	defer d.Mu.Unlock()

	// Rate limit rendering to 10 FPS to prevent flickering and terminal overload
	if time.Since(d.LastRender) < 100*time.Millisecond {
		return
	}
	d.LastRender = time.Now()

	// Clear screen using ANSI (Move cursor to 0,0 and clear down)
	fmt.Print("\033[H\033[J")

	header := color.New(color.BgHiBlue, color.FgWhite, color.Bold)
	
	header.Printf(" GoVult v9.0 | Verified Auditor | %s \n", d.LastRender.Format("15:04:05"))
	fmt.Println(strings.Repeat("-", 70))

	fmt.Printf(" Target:         %s\n", color.HiWhiteString(d.Target))
	fmt.Printf(" Uptime:         %s\n", time.Since(d.StartTime).Round(time.Second))
	fmt.Printf(" Discovery:      %d unique assets identified\n", d.Assets)
	fmt.Printf(" Scanning:       %s\n", d.CurrentTask)
	
	// Progress Bar
	barWidth := 40
	completed := int(d.Progress * float64(barWidth) / 100)
	if completed > barWidth { completed = barWidth }
	if completed < 0 { completed = 0 }
	
	bar := strings.Repeat("█", completed) + strings.Repeat("░", barWidth-completed)
	fmt.Printf("[%s] %.2f%%\n", color.GreenString(bar), d.Progress)

	fmt.Println(strings.Repeat("-", 70))
	
	// Stats Table
	color.Red("  CRITICAL : %d", d.VulnCount["critical"])
	color.HiRed("  HIGH     : %d", d.VulnCount["high"])
	color.Yellow("  MEDIUM   : %d", d.VulnCount["medium"])
	color.Blue("  LOW      : %d", d.VulnCount["low"])

	fmt.Println("\n" + strings.Repeat("-", 70))
	fmt.Println(color.HiBlackString(" [Ghost Mode] [Proxy Rotator] [Verification Engine Active]"))
}
