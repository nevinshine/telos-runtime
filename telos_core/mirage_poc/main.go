package main

import (
	"C"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel bpf mirage.bpf.c -- -I../src -D__TARGET_ARCH_x86

func main() {
	targetPid := flag.Int("pid", 0, "Target PID to deceive")
	targetFd := flag.Int("fd", 0, "Target FD to intercept (usually 3 or 4 for cat)")
	flag.Parse()

	if *targetPid == 0 || *targetFd == 0 {
		log.Fatal("Must specify both -pid and -fd")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Remove memlock: %v", err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}

	// Inject our target constants before loading
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("Load BPF spec: %v", err)
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"target_pid": int32(*targetPid),
		"target_fd":  int32(*targetFd),
	}); err != nil {
		log.Fatalf("Rewrite constants: %v", err)
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Load and assign BPF: %v", err)
	}
	defer objs.Close()

	// 1. Attach Entry Hook (kprobe)
	kp, err := link.Kprobe("ksys_read", objs.MirageSysReadEnter, nil)
	if err != nil {
		log.Fatalf("Link kprobe: %v", err)
	}
	defer kp.Close()

	// 2. Attach Exit Hook (kretprobe)
	krp, err := link.Kretprobe("ksys_read", objs.MirageSysReadExit, nil)
	if err != nil {
		log.Fatalf("Link kretprobe: %v", err)
	}
	defer krp.Close()

	fmt.Printf("[*] Mirage Fallback POC Active.\n[*] Targeting PID: %d, FD: %d\n", *targetPid, *targetFd)
	fmt.Println("[*] Press Ctrl+C to exit.")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}
