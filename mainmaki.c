#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>

#define BUFFER_SIZE 1024
#define MAX_SNAPSHOTS 30

typedef struct
{
    char current[30];
    char previous[30];
} Snapshot;

void copy_file(const char *source, const char *destination)
{
    int source_fd, destination_fd;
    ssize_t bytes_read, bytes_written;
    char buffer[BUFFER_SIZE];

    if ((source_fd = open(source, O_RDONLY)) == -1)
    {
        perror("Error opening source file");
        exit(EXIT_FAILURE);
    }

    if ((destination_fd = open(destination, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) == -1)
    {
        perror("Error opening destination file");
        exit(EXIT_FAILURE);
    }

    while ((bytes_read = read(source_fd, buffer, BUFFER_SIZE)) > 0)
    {
        if ((bytes_written = write(destination_fd, buffer, bytes_read)) != bytes_read)
        {
            perror("Error writing to destination file");
            exit(EXIT_FAILURE);
        }
    }

    if (bytes_read == -1)
    {
        perror("Error reading from source file");
        exit(EXIT_FAILURE);
    }

    if (close(source_fd) == -1)
    {
        perror("Error closing source file");
        exit(EXIT_FAILURE);
    }

    if (close(destination_fd) == -1)
    {
        perror("Error closing destination file");
        exit(EXIT_FAILURE);
    }
}

int compare_snapshots(const char *snapshot1, const char *snapshot2)
{
    int fd1, fd2;
    ssize_t bytes_read1, bytes_read2;
    char buffer1[BUFFER_SIZE];
    char buffer2[BUFFER_SIZE];

    if ((fd1 = open(snapshot1, O_RDONLY)) == -1)
    {
        perror("Error opening first snapshot file");
        exit(EXIT_FAILURE);
    }

    if ((fd2 = open(snapshot2, O_RDONLY)) == -1)
    {
        perror("Error opening second snapshot file");
        exit(EXIT_FAILURE);
    }

    while ((bytes_read1 = read(fd1, buffer1, BUFFER_SIZE)) > 0 && (bytes_read2 = read(fd2, buffer2, BUFFER_SIZE)) > 0)
    {
        if ((bytes_read1 != bytes_read2) || memcmp(buffer1, buffer2, bytes_read1) != 0)
        {
            if (close(fd1) == -1 || close(fd2) == -1)
            {
                perror("Error closing snapshot files");
                exit(EXIT_FAILURE);
            }
            return 1; // Different
        }
    }

    if (bytes_read1 == -1 || bytes_read2 == -1)
    {
        perror("Error reading from snapshot files");
        exit(EXIT_FAILURE);
    }

    if (close(fd1) == -1 || close(fd2) == -1)
    {
        perror("Error closing snapshot files");
        exit(EXIT_FAILURE);
    }

    return 0; // Identical
}

void list_directory(const char *path, int file_descriptor, const char *malicious_dir)
{
    struct dirent *entry;
    DIR *directory;
    struct stat info;
    char filepath[1000];
    char buffer[BUFFER_SIZE];
    time_t modification_time;
    struct tm *mod_time_info;
    char mod_time_str[20];

    if ((directory = opendir(path)) == NULL)
    {
        perror("Error opening directory");
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(directory)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        sprintf(filepath, "%s/%s", path, entry->d_name);

        if (lstat(filepath, &info) == -1)
        {
            perror("Error getting file information");
            exit(EXIT_FAILURE);
        }

        if (S_ISREG(info.st_mode))
        {
            int file_descriptor_copy = dup(file_descriptor); // Duplicate file descriptor
            if (file_descriptor_copy == -1)
            {
                perror("Error duplicating file descriptor");
                exit(EXIT_FAILURE);
            }

            if (!(info.st_mode & (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH)))
            {
                // File has no read, write, or execute permissions
                // Check if file is malicious
                int pipe_fd[2];
                if (pipe(pipe_fd) == -1)
                {
                    perror("Error creating pipe");
                    exit(EXIT_FAILURE);
                }

                pid_t pid = fork();
                if (pid == -1)
                {
                    perror("Error forking process");
                    exit(EXIT_FAILURE);
                }

                if (pid == 0)
                {
                    close(pipe_fd[0]);               // Close read end of pipe in child process
                    dup2(pipe_fd[1], STDOUT_FILENO); // Redirect stdout to pipe
                    execl("/bin/sh", "sh", "verify_for_malitious.sh", filepath, (char *)NULL);
                    perror("Error executing script");
                    exit(EXIT_FAILURE);
                }
                else
                {
                    close(pipe_fd[1]); // Close write end of pipe in parent process
                    char read_buffer[256];
                    ssize_t nbytes = read(pipe_fd[0], read_buffer, sizeof(read_buffer));
                    if (nbytes > 0)
                    {
                        if (strcmp(read_buffer, "SAFE\n") != 0)
                        {
                            printf("Malicious file found: %s\n", filepath);
                            // Move the file to malicious directory
                            pid_t mv_pid = fork();
                            if (mv_pid == -1)
                            {
                                perror("Error forking process for moving file");
                                exit(EXIT_FAILURE);
                            }

                            if (mv_pid == 0)
                            {
                                execl("/bin/mv", "mv", filepath, malicious_dir, (char *)NULL);
                                perror("Error moving file");
                                exit(EXIT_FAILURE);
                            }
                            else
                            {
                                int mv_status;
                                waitpid(mv_pid, &mv_status, 0);
                                if (WIFEXITED(mv_status) && WEXITSTATUS(mv_status) != 0)
                                {
                                    printf("Failed to move the file\n");
                                }
                            }
                        }
                        else
                        {
                            printf("File is safe: %s\n", filepath);
                        }
                    }
                    close(pipe_fd[0]); // Close read end of pipe in parent process
                    wait(NULL);        // Wait for child process to finish
                }
            }

            // Write file path to output file
            if (write(file_descriptor_copy, filepath, strlen(filepath)) == -1)
            {
                perror("Error writing file path to output file");
                exit(EXIT_FAILURE);
            }

            // Write inode number to output file
            sprintf(buffer, "\nInode: %llu\n", info.st_ino);
            if (write(file_descriptor_copy, buffer, strlen(buffer)) == -1)
            {
                perror("Error writing inode number to output file");
                exit(EXIT_FAILURE);
            }

            // Write file size to output file
            sprintf(buffer, "Number of bytes: %llu\n", info.st_size);
            if (write(file_descriptor_copy, buffer, strlen(buffer)) == -1)
            {
                perror("Error writing file size to output file");
                exit(EXIT_FAILURE);
            }

            // Write last modification time to output file
            modification_time = info.st_mtime;
            mod_time_info = localtime(&modification_time);
            strftime(mod_time_str, sizeof(mod_time_str), "%Y-%m-%d %H:%M:%S", mod_time_info);
            sprintf(buffer, "Last modification date: %s\n", mod_time_str);
            if (write(file_descriptor_copy, buffer, strlen(buffer)) == -1)
            {
                perror("Error writing last modification date to output file");
                exit(EXIT_FAILURE);
            }

            close(file_descriptor_copy);
        }

        if (S_ISDIR(info.st_mode))
        {
            list_directory(filepath, file_descriptor, malicious_dir); // Recursively list directory
        }
    }

    if (closedir(directory) == -1)
    {
        perror("Error closing directory");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s <directory1> <directory2> ... -o <output_directory> -x <malicious_directory>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int out_index = -1, malicious_index = -1;
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-o") == 0)
        {
            out_index = i;
        }
        else if (strcmp(argv[i], "-x") == 0)
        {
            malicious_index = i;
        }
    }

    if (out_index == -1 || malicious_index == -1 || out_index + 1 >= argc || malicious_index + 1 >= argc)
    {
        fprintf(stderr, "Invalid arguments\n");
        exit(EXIT_FAILURE);
    }

    char *output_directory = argv[out_index + 1];
    char *malicious_directory = argv[malicious_index + 1];

    Snapshot snapshots[MAX_SNAPSHOTS];
    int num_snapshots = 0;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-o") != 0 && strcmp(argv[i], "-x") != 0)
        {
            strcpy(snapshots[num_snapshots].current, "");
            strcpy(snapshots[num_snapshots].previous, "");
            num_snapshots++;
        }
        else
        {
            break;
        }
    }

    if (num_snapshots > MAX_SNAPSHOTS)
    {
        fprintf(stderr, "Exceeded maximum number of snapshots\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-o") != 0 && strcmp(argv[i], "-x") != 0)
        {
            pid_t pid = fork();
            if (pid == -1)
            {
                perror("Error forking process");
                exit(EXIT_FAILURE);
            }

            if (pid == 0)
            {
                struct stat test_info;
                sprintf(snapshots[i - 1].current, "%s/snapshot%d", output_directory, i);
                if (lstat(snapshots[i - 1].current, &test_info) == 0)
                {
                    printf("Snapshot already exists: %s\n", snapshots[i - 1].current);
                    sprintf(snapshots[i - 1].previous, "%s/snapshot%d.previous", output_directory, i);
                    copy_file(snapshots[i - 1].current, snapshots[i - 1].previous);
                }
                else
                {
                    printf("Creating new snapshot: %s\n", snapshots[i - 1].current);
                }

                int file_descriptor = open(snapshots[i - 1].current, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
                if (file_descriptor == -1)
                {
                    perror("Error opening output file");
                    exit(EXIT_FAILURE);
                }

                list_directory(argv[i], file_descriptor, malicious_directory);

                if (close(file_descriptor) == -1)
                {
                    perror("Error closing output file");
                    exit(EXIT_FAILURE);
                }

                if (strcmp(snapshots[i - 1].previous, "") != 0)
                {
                    if (compare_snapshots(snapshots[i - 1].current, snapshots[i - 1].previous) == 0)
                    {
                        printf("Snapshot for directory %d is identical\n", i);
                    }
                    else
                    {
                        printf("Snapshot for directory %d is different, changes detected\n", i);
                    }
                }
                else
                {
                    printf("First time creating snapshots, no previous snapshots available\n");
                }

                exit(EXIT_SUCCESS);
            }
        }
        else
        {
            break;
        }
    }

    int status;
    pid_t pid;
    while ((pid = wait(&status)) != -1)
    {
        printf("Child process terminated with pid %d\n", pid);
    }

    return 0;
}
