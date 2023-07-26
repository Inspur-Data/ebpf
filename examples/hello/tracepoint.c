//go:build ignore

#include "common.h"
char __license[] SEC("license") = "Dual MIT/GPL";

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/kmem/mm_page_alloc/format
struct alloc_info {
	/* The first 8 bytes is not allowed to read */
	unsigned long pad;
	unsigned long pfn;
	unsigned int order;
	unsigned int gfp_flags;
	int migratetype;
};
// This tracepoint is defined in mm/page_alloc.c:__alloc_pages_nodemask()
// Userspace pathname: /sys/kernel/tracing/events/kmem/mm_page_alloc
SEC("tracepoint/kmem/mm_page_alloc")
int mm_page_alloc(struct alloc_info *info) {
	bpf_printk("BPF triggered hello word  This is a test message !!!!!\n");
	return 0;
}
