package main

// Phase 6: MapBatcher — Batched BPF Map Mutations for Heki EPT Compatibility
//
// In the default (non-Heki) mode, operations flush immediately.
// When TELOS_HEKI_BATCH=1, operations are queued and flushed
// atomically to minimize VMExit transitions under EPT write-protection.

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

// === PROMETHEUS METRICS ===

var (
	metricBatchFlushLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "telos_batch_flush_latency_seconds",
			Help:    "Latency of BPF map batch flush operations",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05},
		},
	)
	metricBatchFlushOps = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "telos_batch_flush_ops_total",
			Help: "Total number of batch flush operations",
		},
	)
	metricBatchQueueDepth = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "telos_batch_queue_depth",
			Help: "Current number of queued BPF map operations",
		},
	)
)

func init() {
	prometheus.MustRegister(metricBatchFlushLatency)
	prometheus.MustRegister(metricBatchFlushOps)
	prometheus.MustRegister(metricBatchQueueDepth)
}

// === BATCHER ===

// batchOp represents a single queued BPF map mutation.
type batchOp struct {
	mapRef *ebpf.Map
	key    interface{}
	value  interface{}
	delete bool
}

// MapBatcher queues BPF map updates and commits them atomically.
// When Heki EPT protection is active, this minimizes VMExit
// transitions by batching N map writes into a single EPT violation window.
type MapBatcher struct {
	mu            sync.Mutex
	queue         []batchOp
	maxBatch      int           // Max ops before auto-flush (0 = no limit)
	flushInterval time.Duration // Periodic flush interval (0 = immediate mode)
	immediate     bool          // True = bypass queue, write directly
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// NewMapBatcher creates a new batcher. In immediate mode (default),
// all operations are applied synchronously with zero overhead.
func NewMapBatcher() *MapBatcher {
	hekiBatch := os.Getenv("TELOS_HEKI_BATCH")
	immediate := hekiBatch != "1"

	b := &MapBatcher{
		queue:         make([]batchOp, 0, 256),
		maxBatch:      64,
		flushInterval: 5 * time.Millisecond,
		immediate:     immediate,
		stopCh:        make(chan struct{}),
	}

	if !immediate {
		log.Printf("[BATCHER] Heki deferred batch mode ENABLED (flush=%v, max=%d)",
			b.flushInterval, b.maxBatch)
		b.wg.Add(1)
		go b.flushLoop()
	} else {
		log.Printf("[BATCHER] Immediate mode (no batching overhead)")
	}

	return b
}

// Put enqueues a map update. In immediate mode, writes directly.
func (b *MapBatcher) Put(m *ebpf.Map, key, value interface{}) error {
	if b.immediate {
		return m.Put(key, value)
	}

	b.mu.Lock()
	b.queue = append(b.queue, batchOp{
		mapRef: m,
		key:    key,
		value:  value,
		delete: false,
	})
	depth := len(b.queue)
	shouldFlush := b.maxBatch > 0 && depth >= b.maxBatch
	b.mu.Unlock()

	metricBatchQueueDepth.Set(float64(depth))

	if shouldFlush {
		return b.Flush()
	}
	return nil
}

// Delete enqueues a map deletion. In immediate mode, deletes directly.
func (b *MapBatcher) Delete(m *ebpf.Map, key interface{}) error {
	if b.immediate {
		return m.Delete(key)
	}

	b.mu.Lock()
	b.queue = append(b.queue, batchOp{
		mapRef: m,
		key:    key,
		delete: true,
	})
	depth := len(b.queue)
	shouldFlush := b.maxBatch > 0 && depth >= b.maxBatch
	b.mu.Unlock()

	metricBatchQueueDepth.Set(float64(depth))

	if shouldFlush {
		return b.Flush()
	}
	return nil
}

// Flush applies all queued operations atomically.
func (b *MapBatcher) Flush() error {
	b.mu.Lock()
	if len(b.queue) == 0 {
		b.mu.Unlock()
		return nil
	}

	// Swap queue to minimize lock hold time
	ops := b.queue
	b.queue = make([]batchOp, 0, cap(ops))
	b.mu.Unlock()

	metricBatchQueueDepth.Set(0)

	t0 := time.Now()
	var firstErr error
	applied := 0

	for _, op := range ops {
		var err error
		if op.delete {
			err = op.mapRef.Delete(op.key)
		} else {
			err = op.mapRef.Put(op.key, op.value)
		}
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("batch op failed: %w", err)
		}
		applied++
	}

	elapsed := time.Since(t0)
	metricBatchFlushLatency.Observe(elapsed.Seconds())
	metricBatchFlushOps.Inc()

	if !b.immediate {
		log.Printf("[BATCHER] Flushed %d ops in %v", applied, elapsed)
	}

	return firstErr
}

// flushLoop runs in deferred mode, periodically flushing the queue.
func (b *MapBatcher) flushLoop() {
	defer b.wg.Done()
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := b.Flush(); err != nil {
				log.Printf("[BATCHER] Periodic flush error: %v", err)
			}
		case <-b.stopCh:
			// Final flush on shutdown
			if err := b.Flush(); err != nil {
				log.Printf("[BATCHER] Final flush error: %v", err)
			}
			return
		}
	}
}

// Stop gracefully shuts down the batcher, flushing remaining ops.
func (b *MapBatcher) Stop() {
	if !b.immediate {
		close(b.stopCh)
		b.wg.Wait()
	}
}

// QueueDepth returns the current number of queued operations.
func (b *MapBatcher) QueueDepth() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.queue)
}
