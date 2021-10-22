#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <limits.h>

#define SIZE 1024
#define MAX_MSG 1024

typedef struct status_message
{
  int status;
  char msg[MAX_MSG];
} StatusMessage;

// return true if the file specified by the filename exists
bool file_not_empty(const char *filename)
{
  FILE *fp;
  bool is_exist;
  int size;

  is_exist = false;
  fp = fopen(filename, "r");
  if (fp != NULL)
  {
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    if (0 < size)
    {
      is_exist = true;
    }
    fclose(fp); // close the file
  }
  return is_exist;
}

// decompress the recieved tar.gz file, enumerate filenames, check if exists, and return sucess or error
int decompress_files(const char *recieved_filename, char **filenames, int files_count)
{
  int i;
  int err;
  char cmd[PATH_MAX];

  if (snprintf(cmd, sizeof(cmd), "sudo tar -zxvf %s", recieved_filename) >= sizeof(cmd))
  {
    return EXIT_FAILURE;
  }

  fflush(NULL);

  err = system(cmd);
  if (err)
  {
    fprintf(stderr, "command failed: %s (%d)\n", cmd, err);
    return EXIT_FAILURE;
  }

  for (i = 0; i < files_count; i++)
  {
    if (!file_not_empty(filenames[i]))
    {
      fprintf(stderr, "recieved file was missing/empty: %s\n", filenames[i]);
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}

// example from https://github.com/omair18/Sock0et-Programming-in-C
int write_file(int sockfd, const char *filename)
{
  FILE *fp;

  fp = fopen(filename, "w");
  ssize_t n;
  ssize_t total = 0;

  char buff[SIZE] = {0};
  while ((n = recv(sockfd, buff, SIZE, 0)) > 0)
  {
    total += n;
    if (n == -1)
    {
      perror("Receive File Error");
      return EXIT_FAILURE;
    }

    if (fwrite(buff, sizeof(char), n, fp) != n)
    {
      perror("Write File Error");
      return EXIT_FAILURE;
    }
    memset(buff, 0, SIZE);
  }

  return EXIT_SUCCESS;
}

// enumerate filenames, check if exists, and compress to one tar.gz file
int clean_files(const char *output_filename, char **filenames, int files_count)
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
      memcpy(filenames_flat + count, filenames[i], strlen(filenames[i]));
      count += strlen(filenames[i]) + 1;
      filenames_flat[count - 1] = ' ';
    }
  }
  else
  {
    free(filenames_flat);
    return EXIT_FAILURE;
  }

  if (snprintf(cmd, sizeof(cmd), "sudo rm -f %s %s", output_filename, filenames_flat) >= sizeof(cmd))
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

int send_status(char *ip, int port, int status, const char message[], ssize_t message_len)
{
  int e;
  int sockfd;
  struct sockaddr_in server_addr;

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

  StatusMessage status_message;
  status_message.status = 1;
  strncpy(status_message.msg, message, message_len);

  int send_status = send(sockfd, (void *)&status_message, sizeof(status_message), 0);
  printf("sent %d bytes\n", send_status);

  printf("[+]Closing the connection.\n");
  close(sockfd);

  return EXIT_SUCCESS;
}

int recieve_file(char *ip, int port, char *recieved_file_name, int* pid)
{
  struct sockaddr_in server_addr, new_addr;
  socklen_t addr_size;
  int sockfd;
  int new_sock;
  int e;

  printf("[+]Createing server socket.\n");

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
    return EXIT_FAILURE;
  }

  addr_size = sizeof(new_addr);
  new_sock = accept(sockfd, (struct sockaddr *)&new_addr, &addr_size); // TODO: verify ip of host??

  char buff[SIZE] = {0};
  int n = recv(new_sock, buff, SIZE, 0);
  if(n <= 0)
  {
    return EXIT_FAILURE;
  }
  *pid = atoi(buff);

  if (write_file(new_sock, recieved_file_name))
  {
    return EXIT_FAILURE;
  }

  printf("[+]Data written in the file successfully.\n");

  printf("[+]Closing the connection.\n");
  close(sockfd);
  close(new_sock);

  return EXIT_SUCCESS;
}

void exec_command(char* rm_cmd){
  int child_pid = fork();
  if (0 > child_pid)
  { // then, error
      perror("fork failed");
      exit(EXIT_FAILURE);
  }
  else
  {
      if (!child_pid)
      { // child
          int err = system(rm_cmd);
          if (err)
          {
              fprintf(stderr, "command failed: %s (%d)\n", rm_cmd, err);
              exit(EXIT_FAILURE);
          }
      }
  }
}

int main(int argc, char *argv[])
{
  int count;
  int port = 8080;
  int pid, time = 3;
  char str[PATH_MAX];
  char *pss_bin = "../../../build/bin/pss_run_example";
  char *rdma_device = "mlx5_2";
  char *ip_BF = "192.168.100.2";
  char *ip_host = "192.168.100.1";
  char *compressed_file = "compressed.tar.gz";
  char *filenames[] = {"mem_regions.json", "symbols.json", "hash.json"};

  if (argc == 7)
  {
    printf("input rdma device: %s\ninput pss bin: %s\ninput time: %s\ninput BF-ip: %s\ninput host-ip: %s\ninput comm-port: %s\n", argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]);
    rdma_device = argv[1];
    pss_bin = argv[2];
    time = atoi(argv[3]);
    ip_BF = argv[4];
    ip_host = argv[5];
    port = atoi(argv[6]);
  }
  else if(argc == 3)
  {
    rdma_device = argv[1];
    pss_bin = argv[2];
    printf("argument expected: rdma-device, pss-bin, scan-time, BF-ip, host-ip, comm-port.\ne.g. \"%s mlx5_2 pss_run_example_path 192.168.100.2 192.168.100.1 8080\"\n", argv[0]);
    printf("using defaults:\nrdma device: %s\npss bin: %s\ndefault time: %d\ndefault BF-ip: %s\ndefault host-ip: %s\ndefault comm-port: %d\n\n",rdma_device,pss_bin,time, ip_BF, ip_host, port);
  }
  else
  {
    printf("argument expected: rdma-device, pss-bin, scan-time, BF-ip, host-ip, comm-port.\ne.g. \"%s mlx5_2 pss_run_example_path 192.168.100.2 192.168.100.1 8080\"\n", argv[0]);
    printf("using defaults:\ndefault rdma device: %s\ndefault pss bin: %s\ndefault time: %d\ndefault BF-ip: %s\ndefault host-ip: %s\ndefault comm-port: %d\n\n",rdma_device,pss_bin,time, ip_BF, ip_host, port);
  }

  count = sizeof(filenames) / sizeof(char *);
  if (clean_files(compressed_file, filenames, count))
  {
    // TODO: exit if I couldn't clean files?
    printf("couldn't clean environment (existsing files), exiting...");
    exit(EXIT_FAILURE);
  }

  if (recieve_file(ip_BF, port, compressed_file, &pid))
  {
    exit(EXIT_FAILURE);
  }
  printf("pid: %d\n", pid);

  count = sizeof(filenames) / sizeof(char *);
  if (decompress_files(compressed_file, filenames, count))
  {
    exit(EXIT_FAILURE);
  }

  pid_t wpid;
  int status = 0;
  pid_t child_pid;

  snprintf(str, sizeof(str), "%s -p %d -e hash.json -m mem_regions.json -o symbols.json -f %s -r %s -t %d", 
          pss_bin, pid, rdma_device, rdma_device, time);
  printf("starting pss process\n");
  exec_command(str);

  printf("sending confirmation to: %s\n", ip_host);
  const char message[] = "All files recieved!";
  if (send_status(ip_host, port + 1, 1, message, sizeof(message)))
  {
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
