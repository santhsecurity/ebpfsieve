#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_RINGBUF 27

#define MAX_SAMPLE 128

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
};

SEC(".maps")
struct bpf_map_def thresholds = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u8),
    .value_size = sizeof(u16),
    .max_entries = 256,
};

SEC(".maps")
struct bpf_map_def rb = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 4096 * 1024,
};

struct skip_decision {
    u64 inode;
    u64 file_offset;
    u64 skip_length;
};

static long (* const bpf_probe_read_user)(void *dst, u32 size, const void *unsafe_ptr) = (void *) 112;
static long (* const bpf_probe_read_kernel)(void *dst, u32 size, const void *unsafe_ptr) = (void *) 113;
static void *(* const bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (* const bpf_ringbuf_output)(void *ringbuf, void *data, u64 size, u64 flags) = (void *) 130;

static __attribute__((always_inline)) int emit_skip(long long file_offset, unsigned long long count) {
    struct skip_decision sd = {
        .inode = 0,
        .file_offset = (u64)file_offset,
        .skip_length = count,
    };
    bpf_ringbuf_output(&rb, &sd, sizeof(sd), 0);
    return 0;
}

SEC("fexit/vfs_read")
int sieve_vfs_read(void *ctx) {
    unsigned long long *args = (unsigned long long *)ctx;
    char *buf = (char *)args[1];
    long long *pos_ptr = (long long *)args[3];
    long long ret = (long long)args[4];

    if (ret <= 0) {
        return 0;
    }

    unsigned long long actual_len = (unsigned long long)ret;
    if (actual_len == 0) {
        return 0;
    }

    long long pos_end = 0;
    bpf_probe_read_kernel(&pos_end, sizeof(pos_end), pos_ptr);
    long long file_offset = 0;
    if ((unsigned long long)pos_end >= actual_len) {
        file_offset = (long long)((unsigned long long)pos_end - actual_len);
    } else {
        file_offset = 0;
    }

    // For reads larger than the sample window, the sampled bytes are not enough
    // to decide the whole read, but if the actual read is smaller than a required
    // threshold then no window inside it can possibly satisfy that threshold.
    if (actual_len > MAX_SAMPLE) {
        if (actual_len > 0xFFFF) {
            return 0;
        }
        for (int b = 0; b < 256; b++) {
            u8 key = (u8)b;
            u16 *threshold = (u16 *)bpf_map_lookup_elem(&thresholds, &key);
            if (threshold && actual_len < *threshold) {
                return emit_skip(file_offset, actual_len);
            }
        }
        return 0;
    }

    unsigned char sample[MAX_SAMPLE];
    if (bpf_probe_read_user(sample, (u32)actual_len, buf) != 0) {
        return 0;
    }

    unsigned char counts[256] = {0};
    for (unsigned long long i = 0; i < actual_len; i++) {
        counts[sample[i]]++;
    }

    for (int b = 0; b < 256; b++) {
        u8 key = (u8)b;
        u16 *threshold = (u16 *)bpf_map_lookup_elem(&thresholds, &key);
        if (threshold && counts[b] < *threshold) {
            return emit_skip(file_offset, actual_len);
        }
    }

    return 0;
}

SEC("license")
char _license[] = "GPL";
