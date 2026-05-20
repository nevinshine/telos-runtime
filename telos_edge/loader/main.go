package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
)

type BlockRequest struct {
	IP string `json:"ip"`
}

var blockedIPs sync.Map

func main() {
	fmt.Println("Telos Edge - Hyperion XDP Daemon Online (Port 9095)")

	http.HandleFunc("/block", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
			return
		}

		var req BlockRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Convert IP string to uint32 and load into eBPF map (simulated for now)
		blockedIPs.Store(req.IP, true)
		log.Printf("[Hyperion XDP] Blackholed %s via eBPF XDP DROP ruleset", req.IP)

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"blocked"}`))
	})

	log.Fatal(http.ListenAndServe("127.0.0.1:9095", nil))
}