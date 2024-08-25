#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static const char MAP_PATH[] = "/sys/fs/bpf/tc/globals/boot_to_wall_off_ns";

int main(int argc, char **argv)
{
        printf("seeding boot_to_wall_off_ns\n");
        int fd, ret;

        // Get pinned BPF map.
        fd = bpf_obj_get(MAP_PATH);
        if (fd < 0)
                goto cleanup;

	// Compute difference between boot and wall time.
	struct timespec boot, wall;
	ret = clock_gettime(CLOCK_BOOTTIME, &boot);
	if (ret < 0) 
                goto cleanup;

	ret = clock_gettime(CLOCK_REALTIME, &wall);
	if (ret < 0)
                goto cleanup;

	__u64 boot_ns = 1000000000 * boot.tv_sec + boot.tv_nsec;
	__u64 wall_ns = 1000000000 * wall.tv_sec + wall.tv_nsec;
	__u64 boot_to_wall_off_ns = wall_ns - boot_ns;

	// Insert at key 0.
 	__u32 k = 0;
        ret = bpf_map_update_elem(fd, &k, &boot_to_wall_off_ns, 0);
        if (ret < 0)
                goto cleanup;

cleanup:
        printf("cleaning up\n");
        close(fd);
        return 0;
}

