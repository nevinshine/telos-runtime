package main

import (
	"fmt"
	"github.com/cilium/ebpf"
)

func main() {
	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/telos/process_map", nil)
	if err != nil {
		panic(err)
	}
	key := make([]byte, 4)
	val := make([]byte, 28) // ProcessInfo size
	err = m.Update(key, val, ebpf.UpdateAny)
	fmt.Printf("Update err: %v\n", err)
}
