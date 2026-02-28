#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define THREADS 100
#define IO_ITERATIONS 100000
#define EXEC_ITERATIONS 1000
#define NET_ITERATIONS 100000

extern char **environ;

// Timing helper
long long time_diff_ns(struct timespec *start, struct timespec *end) {
  return ((end->tv_sec - start->tv_sec) * 1000000000LL) +
         (end->tv_nsec - start->tv_nsec);
}

// 1. File IO Torture (lsm/file_open)
void *torture_open(void *arg) {
  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);

  for (int i = 0; i < IO_ITERATIONS; i++) {
    int fd = open("/tmp/telos_secret.txt", O_RDONLY);
    if (fd >= 0)
      close(fd);
  }

  clock_gettime(CLOCK_MONOTONIC, &end);
  long long *total_ns = malloc(sizeof(long long));
  *total_ns = time_diff_ns(&start, &end);
  return total_ns;
}

// 2. Execution Gate Torture (bprm_check_security)
void *torture_exec(void *arg) {
  struct timespec start, end;
  pid_t pid;
  char *argv[] = {"/bin/true", NULL};

  clock_gettime(CLOCK_MONOTONIC, &start);

  for (int i = 0; i < EXEC_ITERATIONS; i++) {
    // posix_spawn is faster and safer in multithreaded benchmarks than
    // fork/exec
    if (posix_spawn(&pid, "/bin/true", NULL, NULL, argv, environ) == 0) {
      waitpid(pid, NULL, 0);
    }
  }

  clock_gettime(CLOCK_MONOTONIC, &end);
  long long *total_ns = malloc(sizeof(long long));
  *total_ns = time_diff_ns(&start, &end);
  return total_ns;
}

// 3. Network Gate Torture (lsm/socket_connect)
void *torture_connect(void *arg) {
  struct timespec start, end;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(9999); // Dummy port
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

  clock_gettime(CLOCK_MONOTONIC, &start);

  for (int i = 0; i < NET_ITERATIONS; i++) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
      // We expect this to be blocked by Telos or instantly rejected by the OS
      connect(sock, (struct sockaddr *)&addr, sizeof(addr));
      close(sock);
    }
  }

  clock_gettime(CLOCK_MONOTONIC, &end);
  long long *total_ns = malloc(sizeof(long long));
  *total_ns = time_diff_ns(&start, &end);
  return total_ns;
}

void run_test(const char *name, void *(*test_func)(void *), int iter_count) {
  pthread_t threads[THREADS];
  long long total_time_ns = 0;

  for (int i = 0; i < THREADS; i++) {
    pthread_create(&threads[i], NULL, test_func, NULL);
  }

  for (int i = 0; i < THREADS; i++) {
    long long *thread_time;
    pthread_join(threads[i], (void **)&thread_time);
    total_time_ns += *thread_time;
    free(thread_time);
  }

  long long ops = (long long)THREADS * iter_count;
  double avg_us = (double)total_time_ns / ops / 1000.0;

  printf("[*] %-15s | Ops: %lld | Avg Latency: %.3f µs/op\n", name, ops,
         avg_us);
}

int main() {
  printf("=== TELOS HIGH TORTURE BENCHMARK ===\n");
  printf("Threads: %d | IO/Net Iters: %d | Exec Iters: %d\n\n", THREADS,
         IO_ITERATIONS, EXEC_ITERATIONS);

  // Ensure test file exists for open() test
  FILE *f = fopen("/tmp/telos_secret.txt", "w");
  if (f) {
    fputs("test", f);
    fclose(f);
  }

  run_test("File Open", torture_open, IO_ITERATIONS);
  run_test("Execution", torture_exec, EXEC_ITERATIONS);
  run_test("Network Connect", torture_connect, NET_ITERATIONS);

  return 0;
}
