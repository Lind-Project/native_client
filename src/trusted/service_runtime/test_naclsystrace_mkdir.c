#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

int main() {
    char *dirName = "new_directory"; // Name of the directory to create
    struct stat st = {0};

    // Check if directory exists
    if (stat(dirName, &st) == -1) {
        // Directory does not exist, so create it
        if (mkdir(dirName, 0700) == -1) {
            perror("Error creating directory");
            return EXIT_FAILURE;
        } else {
            printf("Directory created successfully.\n");
        }
    } else {
        // Directory exists
        printf("Directory already exists.\n");
    }

    return EXIT_SUCCESS;
}
