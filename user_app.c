#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define PROC_FILE "/proc/process_monitor"

int main() {
    int fd;
    char buffer[1024];
    ssize_t bytes_read;

    fd = open(PROC_FILE, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /proc/process_monitor");
        return -1;
    }

    printf("Process Monitor - Active Processes:\n");
    printf("PID\tName\tState\n");
    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);
    }

    close(fd);
    return 0;
}