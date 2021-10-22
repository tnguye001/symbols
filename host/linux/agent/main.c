#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdbool.h>

#define SIZE 1024
#define MAX_MSG 1024

typedef struct status_message
{
    int status;
    char msg[MAX_MSG];
} StatusMessage;

void exec_bash(char *path)
{
    pid_t wpid;
    int status = 0;
    pid_t child_pid;

    child_pid = fork();
    if (0 > child_pid)
    { // then, error
        perror("fork failed");
        exit(EXIT_FAILURE);
    }
    else
    {
        if (!child_pid)
        { // child
            char str[PATH_MAX];
            snprintf(str, sizeof(str), "%s%s", "sudo /bin/chmod +x ", path);
            int err = system(str);
            if (err)
            {
                fprintf(stderr, "command failed: %s (%d)\n", str, err);
                exit(EXIT_FAILURE);
            }
            execl(path, path, NULL); // TODO: check execl/execve (env vars)
            perror("execl failed");
            exit(EXIT_FAILURE);
        }
    }

    // this way, the father waits for all the child processes
    while ((wpid = wait(&status)) > 0)
    {
    }

    printf("parent running after successful fork\n");
}

// return true if the file specified by the filename exists
bool file_exists(const char *filename)
{
    FILE *fp;
    bool is_exist;

    is_exist = false;
    fp = fopen(filename, "r");
    if (fp != NULL)
    {
        is_exist = true;
        fclose(fp); // close the file
    }
    return is_exist;
}

// enumerate filenames, check if exists, and compress to one tar.gz file
int compress_files(char **filenames, int files_count, const char *output_filename)
{
    int i;
    int sum;
    int count;
    int err;
    char *filenames_flat;
    char cmd[PATH_MAX];

    sum = 0;
    count = 0;
    for (i = 0; i < files_count; i++)
    {
        sum += strlen(filenames[i]) + 1;
    }
    sum++; // Make room for terminating null character

    if ((filenames_flat = calloc(sum, sizeof(char))) != NULL)
    {
        for (i = 0; i < files_count; i++)
        {
            if (file_exists(filenames[i]))
            {
                memcpy(filenames_flat + count, filenames[i], strlen(filenames[i]));
                count += strlen(filenames[i]) + 1;
                filenames_flat[count - 1] = ' ';
            }
            else
            {
                free(filenames_flat);
                return EXIT_FAILURE;
            }
        }
    }
    else
    {
        free(filenames_flat);
        return EXIT_FAILURE;
    }

    if (snprintf(cmd, sizeof(cmd), "sudo tar -czvf %s %s", output_filename, filenames_flat) >= sizeof(cmd))
    {
        free(filenames_flat);
        return EXIT_FAILURE;
    }

    fflush(NULL);

    err = system(cmd);
    if (err)
    {
        fprintf(stderr, "command failed: %s (%d)\n", cmd, err);
        free(filenames_flat);
        return EXIT_FAILURE;
    }

    free(filenames_flat);
    return EXIT_SUCCESS;
}

int recieve_status(char *ip, int port)
{
    int new_sock;
    socklen_t addr_size;
    struct sockaddr_in server_addr, new_addr;
    int sockfd;
    int e;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("[-]Error in socket");
        exit(1);
    }
    printf("[+]Server socket created successfully.\n");

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = port;
    server_addr.sin_addr.s_addr = inet_addr(ip);

    e = bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (e < 0)
    {
        perror("[-]Error in bind");
        exit(1);
    }
    printf("[+]Binding successfull.\n");

    if (listen(sockfd, 1) == 0) // TODO: check if change num-cons from 10 to 1?
    {
        printf("[+]Listening....\n");
    }
    else
    {
        perror("[-]Error in listening");
        exit(1);
    }

    addr_size = sizeof(new_addr);
    new_sock = accept(sockfd, (struct sockaddr *)&new_addr, &addr_size);

    StatusMessage status_message;
    int recv_status = recv(new_sock, (StatusMessage *)&status_message, sizeof(status_message), 0);

    printf("client status %d \n", status_message.status);
    printf("client message %s\n", status_message.msg);
}

int send_file(char *ip, int port, char *file_name, char* first_data_line)
{
    struct sockaddr_in server_addr, new_addr;
    FILE *fp;
    int sockfd;
    int e;
    int n;
    char sendline[SIZE] = {0};
    ssize_t total = 0;

    printf("sending files to: %s\n", ip);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("[-]Error in socket");
        return EXIT_FAILURE;
    }
    printf("[+]Server socket created successfully.\n");

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = port;
    server_addr.sin_addr.s_addr = inet_addr(ip);

    e = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (e == -1)
    {
        perror("[-]Error in socket");
        return EXIT_FAILURE;
    }

    printf("[+]Connected to Server.\n");

    fp = fopen(file_name, "r");
    if (fp == NULL)
    {
        perror("[-]Error in reading file.");
        return EXIT_FAILURE;
    }

    if (send(sockfd, first_data_line, SIZE, 0) == -1)
    {
        perror("Can't send file");
        return EXIT_FAILURE;
    }

    while ((n = fread(sendline, sizeof(char), SIZE, fp)) > 0)
    {
        total += n;
        if (n != SIZE && ferror(fp))
        {
            perror("Read File Error");
            return EXIT_FAILURE;
        }

        if (send(sockfd, sendline, n, 0) == -1)
        {
            perror("Can't send file");
            return EXIT_FAILURE;
        }

        memset(sendline, 0, SIZE);
    }

    printf("[+]File %s sent successfully.\n", file_name);

    printf("[+]Closing the connection.\n");
    close(sockfd);

    return EXIT_SUCCESS;
}

void exec_command(char* rm_cmd){
    int err = system(rm_cmd);
    if (err)
    {
        fprintf(stderr, "command failed: %s (%d)\n", rm_cmd, err);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    int port = 8080;
    char *ip_BF = "192.168.100.2";
    char *ip_host = "192.168.100.1";
    char *compressed_file = "compressed.tar.gz";
    char *filenames[] = {"mem_regions.json", "symbols.json", "hash.json"};
    int err;
    int pid;
    char *bin_path;
    char *rm_cmd;
    size_t count;
    char cwd[PATH_MAX];
    char str[PATH_MAX];

    if (argc == 5)
    {
        printf("input bin: %s\ninput pid: %s\ninput BF-ip: %s\ninput host-ip: %s\ninput comm-port: %s\n", argv[1], argv[2], argv[3], argv[4], argv[5]);
        bin_path = argv[1];
        pid = atoi(argv[2]);
        ip_BF = argv[3];
        ip_host = argv[4];
        port = atoi(argv[5]);
    }
    else if(argc == 3)
    {
        printf("argument expected: bin, pid, BF-ip, host-ip, comm-port.\ne.g. \"%s binary_file_path 1337 192.168.100.2 192.168.100.1 8080\"\n", argv[0]);
        printf("using defaults:\ndefault BF-ip: %s\ndefault host-ip: %s\ndefault comm-port: %d\n\n", ip_BF, ip_host, port);
        bin_path = argv[1];
        pid = atoi(argv[2]);
    }
    else
    {
        printf("argument expected: bin, pid, BF-ip, host-ip, comm-port.\ne.g. \"%s binary_file_path 1337 192.168.100.2 192.168.100.1 8080\"\n", argv[0]);
    }

    if (getcwd(cwd, sizeof(cwd)) != NULL)
    {
        printf("Current working dir: %s\n", cwd);
    }
    else
    {
        perror("getcwd() error");
        return 1;
    }

    exec_command("sudo rm -f hash.json");
    exec_command("mkdir pss_client_build_hash");
    snprintf(str, sizeof(str), "cp %s pss_client_build_hash", bin_path);
    exec_command(str);
    exec_command("python3 hashbuild.py pss_client_build_hash hash.json");

    exec_command("sudo rm -f mem_regions.json");
    snprintf(str, sizeof(str), "%s%s", cwd, "/create_mem_regions.sh");
    exec_bash(str);

    exec_command("sudo rm -f symbols.json");
    snprintf(str, sizeof(str), "%s%s", cwd, "/create_symbols.sh");
    exec_bash(str);

    count = sizeof(filenames) / sizeof(char *);
    if (compress_files(filenames, count, compressed_file))
    {
        exit(EXIT_FAILURE);
    }

    snprintf(str, sizeof(str), "%d", pid);

    if (send_file(ip_BF, port, compressed_file, str))
    {
        exit(EXIT_FAILURE);
    }

    printf("waiting for confirmation, binding to: %s:%d\n", ip_host, port + 1);
    if (recieve_status(ip_host, port + 1))
    {
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}
