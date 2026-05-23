package main

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// LeakMapGVA temporarily attaches a kprobe to extract the kernel virtual address (GVA)
// of the given ebpf.Map by intercepting its update function.
func LeakMapGVA(m *ebpf.Map) (uint64, error) {
	spec, err := ebpf.LoadCollectionSpec(filepath.Join("telos_core", "src", "gva_leaker.o"))
	if err != nil {
		return 0, fmt.Errorf("failed to load gva_leaker.o: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return 0, fmt.Errorf("failed to create gva_leaker collection: %w", err)
	}
	defer coll.Close()

	info, err := m.Info()
	if err != nil {
		return 0, err
	}

	var kprobeProg *ebpf.Program
	var kprobeFunc string

	kprobeProg = coll.Programs["leak_any_map"]
	kprobeFunc = "bpf_map_update_value"

	kp, err := link.Kprobe(kprobeFunc, kprobeProg, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to attach kprobe %s: %w", kprobeFunc, err)
	}
	defer kp.Close()

	// Trigger the map update
	// We use an arbitrary key/val depending on type. Since we don't know the exact sizes,
	// we use a byte slice of the correct size.
	keySz := info.KeySize
	valSz := info.ValueSize
	dummyKey := make([]byte, keySz)
	dummyVal := make([]byte, valSz)

	_ = m.Update(dummyKey, dummyVal, ebpf.UpdateAny)

	// Read the leaked GVA
	var leakKey uint32 = 0
	var leakedGVA uint64
	leakMap := coll.Maps["gva_leak_map"]
	if err := leakMap.Lookup(&leakKey, &leakedGVA); err != nil {
		return 0, fmt.Errorf("failed to lookup leaked GVA: %w", err)
	}

	if leakedGVA == 0 {
		return 0, fmt.Errorf("GVA leak returned 0 (kprobe may not have triggered)")
	}

	// Clean up dummy entry if it's a hash map
	if info.Type == ebpf.Hash || info.Type == ebpf.LRUHash {
		_ = m.Delete(dummyKey)
	}

	return leakedGVA, nil
}
