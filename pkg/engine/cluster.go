package engine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// MasterNode manages workers and distributes tasks
type MasterNode struct {
	Workers []string // Worker addresses (IP:Port)
	Results []Result
	Mu      sync.Mutex
}

// WorkerTask represents a job given to a worker
type WorkerTask struct {
	Target   string   `json:"target"`
	Template string   `json:"template"`
}

func NewMaster() *MasterNode {
	return &MasterNode{}
}

func (m *MasterNode) RegisterWorker(addr string) {
	m.Workers = append(m.Workers, addr)
	fmt.Printf("[MASTER] Worker registered: %s\n", addr)
}

// RunWorker starts a listening worker node
func RunWorker(port int, e *Engine) {
	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		var task WorkerTask
		json.NewDecoder(r.Body).Decode(&task)
		
		fmt.Printf("[WORKER] Executing task: %s on %s\n", task.Template, task.Target)
		// Logic to load template and run scan
		// (Simplified for demo)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Task accepted"))
	})

	fmt.Printf("[WORKER] Listening on port %d...\n", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
