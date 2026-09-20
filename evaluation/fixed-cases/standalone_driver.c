#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);
__attribute__((weak)) void LLVMFuzzerCleanup(void);
__attribute__((weak)) size_t LLVMFuzzerMutate(uint8_t *data, size_t size,
                                              size_t max_size);
#ifdef __cplusplus
}
#endif

__attribute__((weak)) size_t LLVMFuzzerMutate(uint8_t *data, size_t size,
                                              size_t max_size) {
  (void)data;
  return size < max_size ? size : max_size;
}

struct driver_options {
  const char *input_file;
  int input_fd;
  int use_stdin;
};

struct input_buffer {
  uint8_t *data;
  size_t size;
};

static void print_usage(FILE *out, const char *argv0) {
  fprintf(out,
          "Usage:\n"
          "  %s [sample]\n"
          "  %s --input-file sample\n"
          "  %s --stdin\n"
          "  %s --input-fd N\n"
          "\n"
          "Notes:\n"
          "  - No persistent/shared-memory path is used here.\n"
          "  - With no explicit mode and no positional file, the driver reads stdin once.\n"
          "  - For qdmsan-diff/valgrind replay, prefer --input-file @@.\n",
          argv0, argv0, argv0, argv0);
}

static int append_kept_arg(char **argv_out, int *argc_out, int capacity,
                           char *arg) {
  if (*argc_out >= capacity) {
    fprintf(stderr, "driver arg capacity exhausted\n");
    return 1;
  }
  argv_out[*argc_out] = arg;
  (*argc_out)++;
  return 0;
}

static int parse_driver_args(int argc, char **argv, struct driver_options *opts,
                             int *filtered_argc, char ***filtered_argv) {
  int i = 0;
  int outc = 0;
  char **kept = NULL;

  memset(opts, 0, sizeof(*opts));
  opts->input_fd = -1;

  kept = (char **)calloc((size_t)argc + 1, sizeof(char *));
  if (!kept) {
    perror("calloc");
    return 1;
  }

  if (append_kept_arg(kept, &outc, argc + 1, argv[0]) != 0) {
    free(kept);
    return 1;
  }

  for (i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--input-file") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--input-file requires a path\n");
        free(kept);
        return 1;
      }
      opts->input_file = argv[++i];
      continue;
    }

    if (strcmp(argv[i], "--input-fd") == 0) {
      char *end = NULL;
      long fd = 0;
      if (i + 1 >= argc) {
        fprintf(stderr, "--input-fd requires a number\n");
        free(kept);
        return 1;
      }
      fd = strtol(argv[++i], &end, 10);
      if (!end || *end != '\0' || fd < 0 || fd > 0x7fffffffL) {
        fprintf(stderr, "invalid --input-fd value: %s\n", argv[i]);
        free(kept);
        return 1;
      }
      opts->input_fd = (int)fd;
      continue;
    }

    if (strcmp(argv[i], "--stdin") == 0) {
      opts->use_stdin = 1;
      continue;
    }

    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_usage(stdout, argv[0]);
      free(kept);
      exit(0);
    }

    if (append_kept_arg(kept, &outc, argc + 1, argv[i]) != 0) {
      free(kept);
      return 1;
    }
  }

  if (!opts->input_file && opts->input_fd < 0 && !opts->use_stdin && outc == 2) {
    if (strcmp(kept[1], "-") == 0) {
      opts->use_stdin = 1;
    } else if (kept[1][0] != '-') {
      opts->input_file = kept[1];
    }
    outc = 1;
  }

  kept[outc] = NULL;
  *filtered_argc = outc;
  *filtered_argv = kept;
  return 0;
}

static int ensure_capacity(uint8_t **buf, size_t *cap, size_t need) {
  size_t next_cap = 0;
  uint8_t *tmp = NULL;

  if (*cap >= need) {
    return 0;
  }

  next_cap = (*cap == 0) ? 4096 : *cap;
  while (next_cap < need) {
    if (next_cap > (SIZE_MAX / 2)) {
      next_cap = need;
      break;
    }
    next_cap *= 2;
  }

  tmp = (uint8_t *)realloc(*buf, next_cap);
  if (!tmp) {
    perror("realloc");
    return 1;
  }

  *buf = tmp;
  *cap = next_cap;
  return 0;
}

static int read_all_from_fd(int fd, struct input_buffer *out) {
  uint8_t *buf = NULL;
  size_t cap = 0;
  size_t len = 0;

  memset(out, 0, sizeof(*out));

  while (1) {
    ssize_t n = 0;

    if (ensure_capacity(&buf, &cap, len + 4096) != 0) {
      free(buf);
      return 1;
    }

    n = read(fd, buf + len, cap - len);
    if (n == 0) {
      break;
    }
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("read");
      free(buf);
      return 1;
    }
    len += (size_t)n;
  }

  out->data = buf;
  out->size = len;
  return 0;
}

static int read_all_from_path(const char *path, struct input_buffer *out) {
  int fd = open(path, O_RDONLY);
  int rc = 0;

  if (fd < 0) {
    fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
    return 1;
  }

  rc = read_all_from_fd(fd, out);
  close(fd);
  return rc;
}

static int run_one_input(const uint8_t *data, size_t size) {
  static const uint8_t empty_byte = 0;
  const uint8_t *safe_data = data ? data : &empty_byte;
  return LLVMFuzzerTestOneInput(safe_data, size);
}

int main(int argc, char **argv) {
  struct driver_options opts;
  struct input_buffer input;
  int filtered_argc = 0;
  char **filtered_argv = NULL;
  int rc = 0;

  if (parse_driver_args(argc, argv, &opts, &filtered_argc, &filtered_argv) != 0) {
    return 2;
  }

  if (LLVMFuzzerInitialize) {
    rc = LLVMFuzzerInitialize(&filtered_argc, &filtered_argv);
    if (rc != 0) {
      fprintf(stderr, "LLVMFuzzerInitialize returned %d\n", rc);
      free(filtered_argv);
      return rc;
    }
  }

  memset(&input, 0, sizeof(input));

  if (opts.input_file) {
    if (read_all_from_path(opts.input_file, &input) != 0) {
      free(filtered_argv);
      return 1;
    }
  } else if (opts.input_fd >= 0) {
    if (read_all_from_fd(opts.input_fd, &input) != 0) {
      free(filtered_argv);
      return 1;
    }
  } else {
    if (!opts.use_stdin && isatty(STDIN_FILENO)) {
      print_usage(stderr, argv[0]);
      free(filtered_argv);
      return 2;
    }
    if (read_all_from_fd(STDIN_FILENO, &input) != 0) {
      free(filtered_argv);
      return 1;
    }
  }

  rc = run_one_input(input.data, input.size);
  free(input.data);

  if (LLVMFuzzerCleanup) {
    LLVMFuzzerCleanup();
  }

  free(filtered_argv);
  return rc;
}
