// Command collector receives observations POSTed by agents and assembles them
// into per-run paths. Grouping is by run id (the UUID in the payload), which is
// stable even where NAT rewrites the 5-tuple — so a path crosses SNAT/DNAT
// boundaries as one flow.
//
//	POST /               one observation as JSON (what the agent ships)
//	GET  /paths          list run ids with observation counts
//	GET  /path?id=<uuid> the run's observations, ordered by hop then time
//	GET  /healthz
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"sort"
	"sync"

	"github.com/traceflow/traceflow/internal/observation"
)

// maxObsPerRun bounds how many observations a single run id may retain, so one
// chatty or malicious run cannot grow memory without limit. A real path has a
// handful of hops; this is generous headroom for retries and both directions.
const maxObsPerRun = 4096

type store struct {
	mu    sync.Mutex
	runs  map[string][]observation.Observation
	order []string // insertion order of ids, for eviction
	cap   int      // max number of runs retained
}

func newStore(capRuns int) *store {
	return &store{runs: map[string][]observation.Observation{}, cap: capRuns}
}

func (s *store) add(o observation.Observation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[o.ID]; !ok {
		s.order = append(s.order, o.ID)
		for len(s.order) > s.cap {
			old := s.order[0]
			s.order = s.order[1:]
			delete(s.runs, old)
		}
	}
	if len(s.runs[o.ID]) >= maxObsPerRun {
		return // per-run cap reached: drop further observations for this run
	}
	s.runs[o.ID] = append(s.runs[o.ID], o)
}

func (s *store) path(id string) []observation.Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	obs := append([]observation.Observation(nil), s.runs[id]...)
	sort.SliceStable(obs, func(i, j int) bool {
		if obs[i].Hop != obs[j].Hop {
			return obs[i].Hop < obs[j].Hop
		}
		return obs[i].Timestamp < obs[j].Timestamp
	})
	return obs
}

type runSummary struct {
	ID    string `json:"id"`
	Count int    `json:"count"`
}

func (s *store) ids() []runSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]runSummary, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, runSummary{ID: id, Count: len(s.runs[id])})
	}
	return out
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	capRuns := flag.Int("max-runs", 10000, "max distinct run ids retained")
	flag.Parse()

	st := newStore(*capRuns)
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("/paths", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, st.ids())
	})

	mux.HandleFunc("/path", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		writeJSON(w, st.path(id))
	})

	// Root: ingest a single observation.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST an observation", http.StatusMethodNotAllowed)
			return
		}
		var o observation.Observation
		if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if o.ID == "" {
			http.Error(w, "observation missing id", http.StatusBadRequest)
			return
		}
		st.add(o)
		w.WriteHeader(http.StatusNoContent)
	})

	log.Printf("collector listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
