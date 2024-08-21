#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static const char INTF_SCORES_PATH[] = "/sys/fs/bpf/adapt/intf_scores";

jmp_buf jump_destination;

void sigint_handler(int sg)
{
	longjmp(jump_destination, 1);
}

int main(int argc, char **argv)
{
	printf("running interface scoring\n");
	int fd, ret;

	// Handle SIGINT and errors.
	if (setjmp(jump_destination) == 1) {
		goto cleanup;
	}

	// Get pinned interface scores BPF map.
	fd = bpf_obj_get(INTF_SCORES_PATH);
	if (fd < 0) {
		printf("error during bpf open file: %d\n", ret);
		goto cleanup;
	}

	// Insert at key 0.
	__u32 k1 = 0;
	__u32 v1 = 25;
	ret = bpf_map_update_elem(fd, &k1, &v1, 0);
	if (ret < 0) {
		printf("error during bpf map update: %d\n", ret);
		goto cleanup;
	}

	// Lookup at key 0.
	__u32 k2 = 0;
	__u32 v2;
	ret = bpf_map_lookup_elem(fd, &k2, &v2);
	if (ret < 0) {
		printf("error during bpf map lookup: %d\n", ret);
		goto cleanup;
	}
	printf("key: %u, score: %u\n", k2, v2);

	// Spin...
	while (1) { }

cleanup:
	printf("cleaning up\n");
	close(fd);
	return 0;
}

