package main

import (
    "encoding/json"
    "net/http"
    "sync"
	"log"
	"time"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}



// API handler for traffic analysis data
func trafficAnalysisHandler(mu *sync.Mutex, packetCount map[string]int, uniqueIPs map[string]int) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        mu.Lock()
        defer mu.Unlock()

        analysis := TrafficAnalysis{
            PacketCount: packetCount,
            UniqueIPs:   uniqueIPs,
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(analysis)
    }
}

func wsTrafficAnalysisHandler(mu *sync.Mutex, packetCount map[string]int, uniqueIPs map[string]int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			http.Error(w, "Could not open websocket connection", http.StatusBadRequest)
			return
		}
		defer conn.Close()

		for {
			mu.Lock()
			analysis := TrafficAnalysis{
				PacketCount: packetCount,
				UniqueIPs:   uniqueIPs,
			}
			mu.Unlock()

			err = conn.WriteJSON(analysis)
			if err != nil {
				break
			}
			time.Sleep(10 * time.Second)
		}
	}
}

func serveFrontend(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "./frontend/index.html")
}

// Function to start the HTTP server
func startServer(mu *sync.Mutex, packetCount map[string]int, uniqueIPs map[string]int) {
	http.HandleFunc("/", serveFrontend)
    http.HandleFunc("/api/traffic-analysis", trafficAnalysisHandler(mu, packetCount, uniqueIPs))
	http.HandleFunc("/ws/traffic-analysis", wsTrafficAnalysisHandler(mu, packetCount, uniqueIPs))
	log.Println("Starting API server on http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}