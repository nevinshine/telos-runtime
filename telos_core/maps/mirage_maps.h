#ifndef __MIRAGE_MAPS_H
#define __MIRAGE_MAPS_H

#include "../../shared/common_maps.h"

#define MIRAGE_MAP_PATH TELOS_BPF_PATH "/mirage_map"
#define HONEY_DATA_MAP_PATH TELOS_BPF_PATH "/honey_data_map"

/* Map: Inode -> Fake Data ID (to trigger Mirage) */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);   // Inode Number
  __type(value, __u32); // Honey Token ID
} mirage_map SEC(".maps");

struct honey_payload_t {
  __u32 length;
  __u8 data[256]; // Max honey token size for this phase
};

/* Map: Fake Data ID -> Actual Fake Content */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u32); // Honey Token ID
  __type(value, struct honey_payload_t);
} honey_data_map SEC(".maps");

// State to pass from sys_read entry to exit
struct active_mirage_read_t {
  void *user_buf;
  size_t requested_count;
  __u32 honey_id;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u64); // PID/TID
  __type(value, struct active_mirage_read_t);
} active_mirage_reads SEC(".maps");

#endif
