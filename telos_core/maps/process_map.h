// go:build ignore

/*
 * Telos Core - BPF Map Definitions
 *
 * Shared map definitions for the eBPF program.
 * This header is included by bpf_lsm.c.
 */

#ifndef __PROCESS_MAP_H
#define __PROCESS_MAP_H

#include "../../shared/common_maps.h"

/*
 * Map pinning paths
 *
 * Maps are pinned to the BPF filesystem for persistence
 * and access from userspace (Go loader).
 */
#define TELOS_BPF_PATH "/sys/fs/bpf/telos"
#define PROCESS_MAP_PATH TELOS_BPF_PATH "/process_map"
#define CONFIG_MAP_PATH TELOS_BPF_PATH "/config_map"
#define EVENTS_MAP_PATH TELOS_BPF_PATH "/events"

#endif // __PROCESS_MAP_H
