#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

int main() {
    char *dirName = "/root/new_directory"; // An example directory path where you likely don't have permission

    // Attempt to create the directory
    if (mkdir(dirName, 0700) == -1) {
        perror("Error creating directory");
        printf("The errno value is: %d\n", errno);
        return EXIT_FAILURE;
    } else {
        printf("Directory created successfully.\n");
    }

    return EXIT_SUCCESS;
}
