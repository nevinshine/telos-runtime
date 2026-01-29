#ifndef __COMMON_MAPS_H
#define __COMMON_MAPS_H

// Taint Levels (Must match Protocol Buffer Enum)
#define TAINT_CLEAN    0
#define TAINT_LOW      1
#define TAINT_MEDIUM   2
#define TAINT_HIGH     3
#define TAINT_CRITICAL 4

// --- TELOS CORE (LSM) MAPS ---

// Key: PID (Process ID)
// Value: Security State
struct process_info_t {
    __u32 pid;
    __u32 taint_level;     // Current infection level
    __u32 is_sandboxed;    // 1 if running in Docker
    char comm[16];         // Process name (e.g., "python3")
};

// --- TELOS EDGE (XDP) MAPS ---

// Key: Destination IP (Network Byte Order)
// Value: Verdict info
struct flow_rule_t {
    __u32 verdict;         // 1=PASS, 0=DROP
    __u64 expiration_ts;   // Timestamp (ns) when rule expires
    __u32 associated_pid;  // Which agent requested this
};

#endif // __COMMON_MAPS_H
