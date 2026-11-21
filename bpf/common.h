#pragma once

// Shared definitions for all kollektor BPF programs.

#define TASK_COMM_LEN 16

// Default per-probe ring buffer size (must be a power of two multiple of page size).
#define RINGBUF_SIZE (1 << 24)
