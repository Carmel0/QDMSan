/* Standalone QDMSan replay through the AFL++ forkserver and shared-memory ABI. */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "common.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "qdmsan_diff.h"

#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define QDMSAN_DIFF_DEFAULT_TIMEOUT_MS 5000
#define QDMSAN_DIFF_DEFAULT_REPORT_LIMIT 8

static qdmsan_diff_ctx_t *cleanup_ctx;
static volatile sig_atomic_t interrupted_signal;

static int ascii_lower(int c) {

  return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;

}

static int str_eq_ci(const char *s, const char *lit) {

  if (!s || !lit) { return 0; }
  while (*s && *lit) {
    if (ascii_lower((unsigned char)*s) !=
        ascii_lower((unsigned char)*lit)) {
      return 0;
    }
    ++s;
    ++lit;
  }
  return !*s && !*lit;

}

static void signal_cleanup(int sig) {

  int saved_errno = errno;
  interrupted_signal = sig;
  if (cleanup_ctx) {
    cleanup_ctx->stop_soon = 1;
    /* kill is async-signal-safe and wakes a blocked forkserver read. All
       deallocation and shared-memory cleanup runs in normal control flow. */
    if (cleanup_ctx->fsrv.child_pid > 0) {
      kill(cleanup_ctx->fsrv.child_pid, SIGKILL);
    }
    if (cleanup_ctx->fsrv.fsrv_pid > 0) {
      kill(cleanup_ctx->fsrv.fsrv_pid, SIGKILL);
    }
  }
  errno = saved_errno;

}

static void cleanup_at_exit(void) {

  qdmsan_diff_ctx_t *ctx = cleanup_ctx;
  cleanup_ctx = NULL;
  if (ctx) { qdmsan_diff_cleanup(ctx); }
  /* A signal can arrive inside a shared AFL helper that exits on an I/O
     failure. Preserve cancellation status after normal cleanup in that race. */
  if (interrupted_signal) { _exit(128 + interrupted_signal); }

}

static void check_interrupted(void) {

  if (interrupted_signal) { exit(128 + interrupted_signal); }

}

const char *qdmsan_diff_result_name(qdmsan_diff_result_t result) {

  switch (result) {
    case QDMSAN_DIFF_CLEAN:
      return "clean";
    case QDMSAN_DIFF_BUG:
      return "bug";
    case QDMSAN_DIFF_NONDET:
      return "nondet";
    case QDMSAN_DIFF_CRASH:
      return "crash";
    case QDMSAN_DIFF_TIMEOUT:
      return "timeout";
    case QDMSAN_DIFF_ERROR:
      return "error";
    default:
      return "unknown";
  }

}

const char *qdmsan_diff_mode_name(qdmsan_diff_mode_t mode) {

  switch (mode) {
    case QDMSAN_DIFF_MODE_FAST:
      return "fast";
    case QDMSAN_DIFF_MODE_FAST_AUX:
      return "fast+aux";
    case QDMSAN_DIFF_MODE_FULL:
      return "full";
    default:
      return "unknown";
  }

}

const char *qdmsan_diff_check_name(qdmsan_diff_check_t check) {

  return check == QDMSAN_DIFF_CHECK_RESULT ? "result" : "raw";

}

static void die_usage(const char *fmt, ...) {

  if (fmt) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
  }

  fprintf(stderr,
          "usage: qdmsan-diff [options] -- <target> [args...]\n"
          "\n"
          "Options:\n"
          "  -q <path>       afl-qemu-trace path (auto-detected by default)\n"
          "  -l <path>       explicit libqdmsan.so preload path\n"
          "  -m <mode>       fast | fast+aux | full (default: fast)\n"
          "  -c <check>      raw | result (default: raw)\n"
          "  -i <file>       replay file for stdin or @@\n"
          "  -t <ms>         timeout per run, 1..536870911 ms (default: 5000)\n"
          "  -C <n>          extra fast-mode diagnostic triplets, 0..1000 (default: 0)\n"
          "  -R <n>          full-mode report limit (default: 8)\n"
          "  -S              state oracle (compare AFL edge hit-count buckets)\n"
          "  -v              verbose\n"
          "  -Q              quiet result output\n"
          "  -h              show this help\n"
          "\n"
          "Exit codes: 0=clean 1=bug 2=nondet 3=crash 4=timeout 5=error\n");
  exit(QDMSAN_DIFF_ERROR);

}

static u32 parse_u32(const char *name, const char *value, u32 minimum,
                     u32 maximum) {

  if (!value || !*value) { die_usage("%s requires an integer", name); }
  for (const char *p = value; *p; ++p) {
    if (*p < '0' || *p > '9') {
      die_usage("%s requires a decimal integer in [%u, %u]", name, minimum,
                maximum);
    }
  }
  errno = 0;
  char *end = NULL;
  unsigned long long number = strtoull(value, &end, 10);
  if (errno || !end || *end || number < minimum || number > maximum) {
    die_usage("%s requires a decimal integer in [%u, %u]", name, minimum,
              maximum);
  }
  return (u32)number;

}

static u8 parse_bool_off(const char *value) {

  return value && (!strcmp(value, "0") || !strcmp(value, "off") ||
                   !strcmp(value, "false"));

}

static u64 rand_u64(void) {

  return ((u64)rand() << 32) | (u64)rand();

}

static int read_env_u64(const char *name, u64 *out) {

  const char *value = getenv(name);
  if (!value || !*value) { return 0; }

  errno = 0;
  char *end = NULL;
  unsigned long long parsed = strtoull(value, &end, 0);
  if (errno || !end || end == value || *end ||
      value[0] < '0' || value[0] > '9') {
    fprintf(stderr, "qdmsan-diff: ignoring invalid %s='%s'\n", name, value);
    return 0;
  }

  *out = (u64)parsed;
  return 1;

}

static int read_replay_u64(const char *short_name, u64 *out) {

  char name[96];
  snprintf(name, sizeof(name), "AFL_DMSAN_REPLAY_%s", short_name);
  if (read_env_u64(name, out)) { return 1; }
  snprintf(name, sizeof(name), "DMSAN_REPLAY_%s", short_name);
  return read_env_u64(name, out);

}

static void capture_fixed_values(qdmsan_diff_ctx_t *ctx) {

  struct timeval tv;
  gettimeofday(&tv, NULL);
  ctx->fixed_time_sec = (u64)tv.tv_sec;
  ctx->fixed_time_usec = (u64)tv.tv_usec;

  srand((unsigned)(tv.tv_sec ^ tv.tv_usec ^ getpid()));
  ctx->fixed_rand_base = rand_u64();

#if defined(__x86_64__) || defined(__i386__)
  {

    unsigned int lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    ctx->fixed_tsc_base = ((u64)hi << 32) | lo;

  }
#else
  ctx->fixed_tsc_base =
      (u64)tv.tv_sec * 1000000000ULL + (u64)tv.tv_usec * 1000ULL;
#endif

  ctx->fixed_rdrand_base = rand_u64();

  read_replay_u64("FIXED_TIME_SEC", &ctx->fixed_time_sec);
  read_replay_u64("FIXED_TIME_USEC", &ctx->fixed_time_usec);
  read_replay_u64("FIXED_RAND_BASE", &ctx->fixed_rand_base);
  read_replay_u64("FIXED_TSC_BASE", &ctx->fixed_tsc_base);
  read_replay_u64("FIXED_RDRAND_BASE", &ctx->fixed_rdrand_base);

}

static u64 round_pow2(u64 value) {

  u64 out = 1;
  while (out < value) { out <<= 1; }
  return out;

}

static u8 signatures_equal(const struct dmsan_fast_map *a,
                           const struct dmsan_fast_map *b) {

  return qdmsan_fast_signatures_equal(a, b);

}

static const char *plane_mask_name(u8 mask) {

  switch (mask & QDMSAN_PLANE_ALL) {
    case 0:
      return "none";
    case QDMSAN_PLANE_UUM:
      return "UUM";
    case QDMSAN_PLANE_OOB:
      return "OOB";
    case QDMSAN_PLANE_UUM | QDMSAN_PLANE_OOB:
      return "UUM|OOB";
    case QDMSAN_PLANE_UAF:
      return "UAF";
    case QDMSAN_PLANE_UUM | QDMSAN_PLANE_UAF:
      return "UUM|UAF";
    case QDMSAN_PLANE_OOB | QDMSAN_PLANE_UAF:
      return "OOB|UAF";
    case QDMSAN_PLANE_ALL:
      return "UUM|OOB|UAF";
    default:
      return "invalid";
  }

}

static void print_signature(const char *name, const struct dmsan_fast_map *m) {

  printf("  %s: UUM=(0x%016llx,0x%016llx,%llu) "
         "OOB=(0x%016llx,0x%016llx,%llu) "
         "UAF=(0x%016llx,0x%016llx,%llu) abi=0x%016llx\n",
         name, (unsigned long long)m->sum_signature,
         (unsigned long long)m->rotl_signature,
         (unsigned long long)m->total_count,
         (unsigned long long)qdmsan_plane_sum(m, QDMSAN_PLANE_OOB),
         (unsigned long long)qdmsan_plane_rotl(m, QDMSAN_PLANE_OOB),
         (unsigned long long)qdmsan_plane_count(m, QDMSAN_PLANE_OOB),
         (unsigned long long)qdmsan_plane_sum(m, QDMSAN_PLANE_UAF),
         (unsigned long long)qdmsan_plane_rotl(m, QDMSAN_PLANE_UAF),
         (unsigned long long)qdmsan_plane_count(m, QDMSAN_PLANE_UAF),
         (unsigned long long)m->padding[QDMSAN_FAST_ABI_IDX]);

}

static char *xstrdup0(const char *s) {

  if (!s) { return NULL; }
  char *out = strdup(s);
  if (!out) { PFATAL("strdup failed"); }
  return out;

}

static u8 file_executable(const char *path) {

  return path && *path && !access(path, X_OK);

}

static char *path_join(const char *dir, const char *base) {

  char *out = NULL;
  if (asprintf(&out, "%s/%s", dir, base) < 0) { return NULL; }
  return out;

}

static char *dirname_dup(const char *path) {

  char *copy = xstrdup0(path);
  char *slash = strrchr(copy, '/');
  if (!slash) {
    free(copy);
    return xstrdup0(".");
  }
  if (slash == copy) {
    slash[1] = '\0';
  } else {
    *slash = '\0';
  }
  return copy;

}

static char *canonical_exe_dir(void) {

  char buf[4096];
  ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) { return xstrdup0("."); }
  buf[n] = '\0';
  return dirname_dup(buf);

}

static char *find_qemu_path(void) {

  const char *env = getenv("AFL_QDMSAN_QEMU");
  if (file_executable(env)) { return xstrdup0(env); }
  env = getenv("AFL_QEMU_TRACE");
  if (file_executable(env)) { return xstrdup0(env); }

  char *exe_dir = canonical_exe_dir();
  char *candidate = path_join(exe_dir, "../../afl-qemu-trace");
  if (file_executable(candidate)) {
    free(exe_dir);
    return candidate;
  }
  free(candidate);

  candidate = path_join(exe_dir, "afl-qemu-trace");
  if (file_executable(candidate)) {
    free(exe_dir);
    return candidate;
  }
  free(candidate);
  free(exe_dir);

  if (file_executable("./afl-qemu-trace")) { return xstrdup0("./afl-qemu-trace"); }
  if (file_executable("/usr/local/bin/afl-qemu-trace")) {
    return xstrdup0("/usr/local/bin/afl-qemu-trace");
  }

  return NULL;

}

static char *find_libqdmsan_path(void) {

  const char *env = getenv("AFL_QDMSAN_LIB");
  if (env && !access(env, R_OK)) { return xstrdup0(env); }

  char *exe_dir = canonical_exe_dir();
  char *candidate = path_join(exe_dir, "../../libqdmsan.so");
  if (candidate && !access(candidate, R_OK)) {
    free(exe_dir);
    return candidate;
  }
  free(candidate);
  free(exe_dir);

  if (!access("./libqdmsan.so", R_OK)) { return xstrdup0("./libqdmsan.so"); }
  if (!access("/usr/local/lib/afl/libqdmsan.so", R_OK)) {
    return xstrdup0("/usr/local/lib/afl/libqdmsan.so");
  }

  return NULL;

}

static void copy_all(int out_fd, int in_fd, u8 **buf_out, size_t *len_out) {

  size_t cap = 0;
  size_t len = 0;
  u8    *buf = NULL;
  u8     tmp[8192];

  for (;;) {

    check_interrupted();
    ssize_t got = read(in_fd, tmp, sizeof(tmp));
    check_interrupted();
    if (!got) { break; }
    if (got < 0) {
      if (errno == EINTR) { continue; }
      PFATAL("read input failed");
    }
    if ((size_t)got > UINT32_MAX - len) {
      FATAL("input exceeds the forkserver's 32-bit length limit");
    }

    if (out_fd >= 0) {
      ssize_t off = 0;
      while (off < got) {
        ssize_t wrote = write(out_fd, tmp + off, (size_t)(got - off));
        if (wrote < 0) {
          if (errno == EINTR) { check_interrupted(); continue; }
          PFATAL("write input snapshot failed");
        }
        if (!wrote) { FATAL("short write to input snapshot"); }
        off += wrote;
      }
    }

    if (len + (size_t)got > cap) {
      size_t next = cap ? cap * 2 : 8192;
      while (next < len + (size_t)got) { next *= 2; }
      u8 *nbuf = realloc(buf, next);
      if (!nbuf) { PFATAL("realloc input snapshot failed"); }
      buf = nbuf;
      cap = next;
    }
    memcpy(buf + len, tmp, (size_t)got);
    len += (size_t)got;

  }

  *buf_out = buf;
  *len_out = len;

}

static void read_input_file(qdmsan_diff_ctx_t *ctx, const char *path) {

  int fd = open(path, O_RDONLY);
  if (fd < 0) { PFATAL("unable to open -i input file '%s'", path); }
  copy_all(-1, fd, &ctx->input_buf, &ctx->input_len);
  close(fd);

}

static void snapshot_stdin(qdmsan_diff_ctx_t *ctx) {

  struct stat st;
  if (fstat(STDIN_FILENO, &st) != 0) { return; }

  if (S_ISCHR(st.st_mode) && isatty(STDIN_FILENO)) { return; }

  /* A pipe is an input stream, even when its writer has not produced the
     first byte yet. Read until EOF so every replay sees the whole input. */
  copy_all(-1, STDIN_FILENO, &ctx->input_buf, &ctx->input_len);

}

static char *replace_atat(const char *arg, const char *path, u8 *changed) {

  const char *needle = strstr(arg, "@@");
  if (!needle) { return xstrdup0(arg); }

  *changed = 1;
  size_t path_len = strlen(path);
  size_t arg_len = strlen(arg);
  size_t count = 0;
  for (const char *p = arg; (p = strstr(p, "@@")); p += 2) { ++count; }

  size_t out_len = arg_len + count * (path_len - 2) + 1;
  char  *out = ck_alloc(out_len);
  char  *w = out;
  const char *p = arg;
  while ((needle = strstr(p, "@@"))) {
    size_t prefix = (size_t)(needle - p);
    memcpy(w, p, prefix);
    w += prefix;
    memcpy(w, path, path_len);
    w += path_len;
    p = needle + 2;
  }
  strcpy(w, p);
  return out;

}

static void write_replay_input(qdmsan_diff_ctx_t *ctx) {

  if (!ctx->input_buf && ctx->input_len) { PFATAL("invalid input snapshot"); }
  afl_fsrv_write_to_testcase(&ctx->fsrv, ctx->input_buf, ctx->input_len);

}

static void setup_input(qdmsan_diff_ctx_t *ctx, const char *input_file) {

  if (input_file) {
    read_input_file(ctx, input_file);
  } else {
    snapshot_stdin(ctx);
  }

  char template[] = "/tmp/qdmsan-diff-input-XXXXXX";
  ctx->input_fd = mkstemp(template);
  if (ctx->input_fd < 0) { PFATAL("mkstemp failed"); }
  snprintf(ctx->input_path, sizeof(ctx->input_path), "%s", template);

  ctx->owned_target_argv = ck_alloc(sizeof(char *) * (ctx->target_argc + 1));
  for (int i = 0; i < ctx->target_argc; ++i) {
    u8 changed = 0;
    ctx->owned_target_argv[i] =
        replace_atat(ctx->target_argv[i], ctx->input_path, &changed);
    if (changed) { ctx->input_is_file_arg = 1; }
  }
  ctx->owned_target_argv[ctx->target_argc] = NULL;
  ctx->target_argv = ctx->owned_target_argv;
  ctx->target_path = ctx->target_argv[0];

  if (ctx->input_is_file_arg) {
    ctx->fsrv.use_stdin = false;
    ctx->fsrv.out_file = (u8 *)ctx->input_path;
    ctx->fsrv.no_unlink = true;
    close(ctx->input_fd);
    ctx->input_fd = -1;
  } else {
    ctx->fsrv.use_stdin = true;
    ctx->fsrv.out_fd = ctx->input_fd;
    unlink(ctx->input_path);
    ctx->input_path[0] = '\0';
  }

}

static void export_shm_env(qdmsan_diff_ctx_t *ctx) {

  char buf[64];

  snprintf(buf, sizeof(buf), "%d", ctx->shm_fast_id);
  setenv(DMSAN_FAST_SHM_ENV_VAR, buf, 1);

  snprintf(buf, sizeof(buf), "%d", ctx->shm_poison_id);
  setenv(DMSAN_POISON_SHM_ENV_VAR, buf, 1);

  if (ctx->feedback_map) {
    snprintf(buf, sizeof(buf), "%d", ctx->shm_feedback_id);
    setenv(DMSAN_FEEDBACK_SHM_ENV_VAR, buf, 1);
  } else {
    unsetenv(DMSAN_FEEDBACK_SHM_ENV_VAR);
  }

  if (ctx->full_map) {
    snprintf(buf, sizeof(buf), "%d", ctx->shm_full_id);
    setenv(DMSAN_FULL_SHM_ENV_VAR, buf, 1);
  } else {
    unsetenv(DMSAN_FULL_SHM_ENV_VAR);
  }

}

static int same_file(const char *left, const char *right) {

  struct stat a, b;
  return !strcmp(left, right) ||
         (!stat(left, &a) && !stat(right, &b) &&
          a.st_dev == b.st_dev && a.st_ino == b.st_ino);

}

static void prepend_afl_preload(const char *path) {

  if (!path || !*path) { return; }
  if (strpbrk(path, ": \t\n")) {
    die_usage("libqdmsan path contains an unsupported preload separator: %s",
              path);
  }

  const char *old = getenv("AFL_PRELOAD");
  char *joined = xstrdup0(path);
  char *entries = xstrdup0(old ? old : "");
  char *save = NULL;
  for (char *entry = strtok_r(entries, ": \t\n", &save); entry;
       entry = strtok_r(NULL, ": \t\n", &save)) {
    if (same_file(path, entry)) { continue; }
    const char *base = strrchr(entry, '/');
    base = base ? base + 1 : entry;
    if (!strcmp(base, "libqdmsan.so") ||
        !strncmp(base, "libqdmsan.so.", strlen("libqdmsan.so."))) {
      die_usage("AFL_PRELOAD runtime '%s' conflicts with selected runtime '%s'; "
                "remove the conflicting entry", entry, path);
    }
    char *next = NULL;
    if (asprintf(&next, "%s:%s", joined, entry) < 0) {
      PFATAL("asprintf failed");
    }
    free(joined);
    joined = next;
  }
  if (setenv("AFL_PRELOAD", joined, 1)) { PFATAL("setenv AFL_PRELOAD failed"); }
  free(entries);
  free(joined);

}

static void qdmsan_exec_child(afl_forkserver_t *fsrv, char **argv) {

  qdmsan_diff_ctx_t *ctx = (qdmsan_diff_ctx_t *)fsrv->custom_data_ptr;

  export_shm_env(ctx);
  setenv("AFL_USE_QDMSAN", "1", 1);
  setenv("AFL_QDMSAN_MODE", qdmsan_diff_mode_name(ctx->mode), 1);
  setenv("AFL_QDMSAN_CHECK", qdmsan_diff_check_name(ctx->check), 1);
  setenv("AFL_MAP_SIZE", "65536", 1);

  char seed[32];
  snprintf(seed, sizeof(seed), "%llu",
           (unsigned long long)(ctx->fixed_rand_base & 0x7fffffffULL));
  if (!getenv("QEMU_RAND_SEED")) { setenv("QEMU_RAND_SEED", seed, 1); }

  execv((const char *)fsrv->target_path, argv);
  _exit(1);

}

static int setup_shm(qdmsan_diff_ctx_t *ctx) {

  ctx->shm_fast_id =
      shmget(IPC_PRIVATE, sizeof(struct dmsan_fast_map), IPC_CREAT | 0600);
  if (ctx->shm_fast_id < 0) { PFATAL("shmget fast map failed"); }
  ctx->fast_map = shmat(ctx->shm_fast_id, NULL, 0);
  if (ctx->fast_map == (void *)-1) { PFATAL("shmat fast map failed"); }
  memset(ctx->fast_map, 0, sizeof(struct dmsan_fast_map));

  if (ctx->mode == QDMSAN_DIFF_MODE_FAST_AUX) {
    ctx->shm_feedback_id =
        shmget(IPC_PRIVATE, sizeof(struct dmsan_feedback_shm),
               IPC_CREAT | 0600);
    if (ctx->shm_feedback_id < 0) { PFATAL("shmget feedback map failed"); }
    ctx->feedback_map = shmat(ctx->shm_feedback_id, NULL, 0);
    if (ctx->feedback_map == (void *)-1) {
      PFATAL("shmat feedback map failed");
    }
    memset(ctx->feedback_map, 0, sizeof(struct dmsan_feedback_shm));
    ctx->feedback_map->header.magic = DMSAN_FEEDBACK_MAGIC;
    ctx->feedback_map->header.version = DMSAN_FEEDBACK_VERSION;
    ctx->feedback_map->header.map_size = DMSAN_FEEDBACK_MAP_SIZE;
    ctx->feedback_map->header.site_map_entries = DMSAN_SITE_CLASS_ENTRIES;

    ctx->aux1 = ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
    ctx->aux2 = ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
    ctx->aux3 = ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  }

  if (ctx->mode == QDMSAN_DIFF_MODE_FULL) {
    const char *size_env = getenv("AFL_QDMSAN_FULL_SIZE");
    if (size_env && *size_env) {
      ctx->full_entries = parse_u32("AFL_QDMSAN_FULL_SIZE", size_env,
                                    DMSAN_FULL_MIN_SIZE, DMSAN_FULL_MAX_SIZE);
    }
    if (ctx->full_entries < DMSAN_FULL_MIN_SIZE) {
      ctx->full_entries = DMSAN_FULL_MIN_SIZE;
    }
    if (ctx->full_entries > DMSAN_FULL_MAX_SIZE) {
      ctx->full_entries = DMSAN_FULL_MAX_SIZE;
    }
    if (ctx->full_entries & (ctx->full_entries - 1)) {
      ctx->full_entries = round_pow2(ctx->full_entries);
    }

    size_t full_size = sizeof(struct dmsan_full_meta) +
                       (size_t)ctx->full_entries *
                           sizeof(struct dmsan_full_entry);
    ctx->shm_full_id = shmget(IPC_PRIVATE, full_size, IPC_CREAT | 0600);
    if (ctx->shm_full_id < 0) { PFATAL("shmget full map failed"); }
    ctx->full_map = shmat(ctx->shm_full_id, NULL, 0);
    if (ctx->full_map == (void *)-1) { PFATAL("shmat full map failed"); }
    memset(ctx->full_map, 0, full_size);
    ctx->full_map->meta.magic = DMSAN_FULL_MAGIC;
    ctx->full_map->meta.array_size = ctx->full_entries;
    ctx->full_map->meta.mode = DMSAN_FULL_MODE_HASH;
    ctx->full_map->meta.abi_version = DMSAN_FULL_ABI_VERSION;

    ctx->full_entries1 =
        ck_alloc(sizeof(struct dmsan_full_entry) * (size_t)ctx->full_entries);
    ctx->full_entries2 =
        ck_alloc(sizeof(struct dmsan_full_entry) * (size_t)ctx->full_entries);
    ctx->full_entries3 =
        ck_alloc(sizeof(struct dmsan_full_entry) * (size_t)ctx->full_entries);
  }

  ctx->shm_poison_id = shmget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
  if (ctx->shm_poison_id < 0) { PFATAL("shmget poison byte failed"); }
  ctx->poison_byte = shmat(ctx->shm_poison_id, NULL, 0);
  if (ctx->poison_byte == (void *)-1) { PFATAL("shmat poison byte failed"); }
  *ctx->poison_byte = DMSAN_POISON_RUN1;

  return 0;

}

static void clear_maps(qdmsan_diff_ctx_t *ctx) {

  memset(ctx->fast_map, 0, sizeof(struct dmsan_fast_map));
  ctx->fast_map->fixed_time_sec = ctx->fixed_time_sec;
  ctx->fast_map->fixed_time_usec = ctx->fixed_time_usec;
  ctx->fast_map->fixed_rand_base = ctx->fixed_rand_base;
  ctx->fast_map->fixed_tsc_base = ctx->fixed_tsc_base;
  ctx->fast_map->fixed_rdrand_base = ctx->fixed_rdrand_base;

  if (ctx->feedback_map) {
    memset(ctx->feedback_map->site_map, 0, sizeof(ctx->feedback_map->site_map));
    memset(ctx->feedback_map->map, 0, sizeof(ctx->feedback_map->map));
  }

  if (ctx->full_map) {
    memset(ctx->full_map->entries, 0,
           sizeof(struct dmsan_full_entry) * (size_t)ctx->full_entries);
    ctx->full_map->meta.write_index = 0;
    ctx->full_map->meta.total_count = 0;
    ctx->full_map->meta.overflow_count = 0;
  }

}

static void save_snapshot(qdmsan_diff_ctx_t *ctx, int run) {

  struct dmsan_fast_map *fast_dst =
      run == 1 ? &ctx->snap1 : run == 2 ? &ctx->snap2 : &ctx->snap3;
  memcpy(fast_dst, ctx->fast_map, sizeof(*fast_dst));

  if (ctx->state_oracle && ctx->trace_bits) {
    u8 *cov_dst = run == 1 ? ctx->cov1 : run == 2 ? ctx->cov2 : ctx->cov3;
    if (cov_dst) { memcpy(cov_dst, ctx->trace_bits, MAP_SIZE); }
  }

  if (ctx->feedback_map) {
    u16 *aux_dst = run == 1 ? ctx->aux1 : run == 2 ? ctx->aux2 : ctx->aux3;
    memcpy(aux_dst, ctx->feedback_map->site_map,
           sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  }

  if (ctx->full_map) {
    struct dmsan_full_meta *meta_dst =
        run == 1 ? &ctx->full_meta1
                 : run == 2 ? &ctx->full_meta2 : &ctx->full_meta3;
    struct dmsan_full_entry *entries_dst =
        run == 1 ? ctx->full_entries1
                 : run == 2 ? ctx->full_entries2 : ctx->full_entries3;
    memcpy(meta_dst, &ctx->full_map->meta, sizeof(*meta_dst));
    memcpy(entries_dst, ctx->full_map->entries,
           sizeof(struct dmsan_full_entry) * (size_t)ctx->full_entries);
  }

}

static qdmsan_diff_result_t run_one(qdmsan_diff_ctx_t *ctx, u8 poison,
                                    struct dmsan_fast_map *snap, u16 *aux) {

  check_interrupted();
  *ctx->poison_byte = poison;
  clear_maps(ctx);
  /* The coverage map carries hit counts forward between runs here, so the
     state oracle clears it itself and each snapshot holds one run. */
  if (ctx->state_oracle && ctx->trace_bits) {
    memset(ctx->trace_bits, 0, MAP_SIZE);
  }
  write_replay_input(ctx);

  fsrv_run_result_t ret =
      afl_fsrv_run_target(&ctx->fsrv, ctx->timeout_ms, &ctx->stop_soon);
  ++ctx->total_runs;
  check_interrupted();

  if (ret == FSRV_RUN_OK) {
    if (snap) { memcpy(snap, ctx->fast_map, sizeof(*snap)); }
    if (aux && ctx->feedback_map) {
      memcpy(aux, ctx->feedback_map->site_map,
             sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
    }
    return QDMSAN_DIFF_CLEAN;
  }
  if (ret == FSRV_RUN_TMOUT) { return QDMSAN_DIFF_TIMEOUT; }
  if (ret == FSRV_RUN_CRASH) { return QDMSAN_DIFF_CRASH; }
  return QDMSAN_DIFF_ERROR;

}

static qdmsan_diff_result_t run_and_save(qdmsan_diff_ctx_t *ctx, int run,
                                         u8 poison) {

  qdmsan_diff_result_t r = run_one(ctx, poison, NULL, NULL);
  if (r == QDMSAN_DIFF_CLEAN) { save_snapshot(ctx, run); }
  if (ctx->verbose && r == QDMSAN_DIFF_CLEAN) {
    char name[16];
    snprintf(name, sizeof(name), "run%d", run);
    print_signature(name, run == 1 ? &ctx->snap1
                                   : run == 2 ? &ctx->snap2 : &ctx->snap3);
    if (ctx->full_map) {
      struct dmsan_full_meta *m = run == 1 ? &ctx->full_meta1
                                           : run == 2 ? &ctx->full_meta2
                                                      : &ctx->full_meta3;
      printf("    full: total=%llu overflow=%llu size=%llu module_base=0x%llx\n",
             (unsigned long long)m->total_count,
             (unsigned long long)m->overflow_count,
             (unsigned long long)m->array_size,
             (unsigned long long)m->module_base);
    }
  }
  return r;

}

/* Coarse state oracle. The two fills and the repeat run are the same ones the
   checkpoint oracle uses, so only the compared quantity changes. An edge whose
   hit bucket moves with the fill and returns on the repeat marks a poison
   dependent divergence, while an edge that differs between the two runs that
   share a fill marks execution noise. */
/* AFL hit count bucketing. Comparing raw counters would call a loop that runs
   a few more times a divergence, so the state oracle compares the same
   bucketed classes a coverage guided fuzzer stores. */
static u8 cov_bucket(u8 v) {

  if (v == 0) { return 0; }
  if (v == 1) { return 1; }
  if (v == 2) { return 2; }
  if (v == 3) { return 4; }
  if (v <= 7) { return 8; }
  if (v <= 15) { return 16; }
  if (v <= 31) { return 32; }
  if (v <= 127) { return 64; }
  return 128;

}

static qdmsan_diff_result_t cov_maps_verdict(const qdmsan_diff_ctx_t *ctx,
                                             const u8 *m1, const u8 *m2,
                                             const u8 *m3) {

  if (!m1 || !m2 || !m3) { return QDMSAN_DIFF_CLEAN; }

  u8  any_nondet = 0;
  u32 live = 0, diff_fill = 0, diff_repeat = 0;

  for (u32 i = 0; i < MAP_SIZE; ++i) {
    u8 v1 = cov_bucket(m1[i]);
    u8 v2 = cov_bucket(m2[i]);
    u8 v3 = cov_bucket(m3[i]);
    if (!(v1 | v2 | v3)) { continue; }
    ++live;
    if (v1 != v2) { ++diff_fill; }
    if (v1 != v3) {
      ++diff_repeat;
      any_nondet = 1;
    }
  }

  if (ctx && ctx->verbose) {
    printf("  state: live=%u fill_diff=%u repeat_diff=%u\n", live, diff_fill,
           diff_repeat);
  }

  if (!any_nondet && diff_fill) { return QDMSAN_DIFF_BUG; }
  return any_nondet ? QDMSAN_DIFF_NONDET : QDMSAN_DIFF_CLEAN;

}

static qdmsan_diff_result_t aux_maps_verdict(const u16 *m1, const u16 *m2,
                                             const u16 *m3) {

  if (!m1 || !m2 || !m3) { return QDMSAN_DIFF_CLEAN; }

  u8 any_nondet = 0;
  for (u32 i = 0; i < DMSAN_SITE_CLASS_ENTRIES; ++i) {
    u16 v1 = m1[i], v2 = m2[i], v3 = m3[i];
    if (!(v1 | v2 | v3)) { continue; }
    if (v1 == v3 && v1 != v2) { return QDMSAN_DIFF_BUG; }
    if (v1 != v3) { any_nondet = 1; }
  }

  return any_nondet ? QDMSAN_DIFF_NONDET : QDMSAN_DIFF_CLEAN;

}

static int full_entry_empty(const struct dmsan_full_entry *e) {

  return e->value == 0 && e->pc == 0 && e->site_id == 0 && e->flags == 0;

}

static int full_identity_equal(const struct dmsan_full_entry *a,
                               const struct dmsan_full_entry *b) {

  return a->pc == b->pc && a->site_id == b->site_id && a->flags == b->flags;

}

static qdmsan_diff_result_t full_compare(qdmsan_diff_ctx_t *ctx) {

  ctx->last_verdict_aux_rescue = 0;
  ctx->full_compared_slots = 0;
  ctx->full_nondet_slots = 0;
  ctx->full_diff_slots = 0;
  ctx->first_diff_slot = (u64)-1;

  for (u64 i = 0; i < ctx->full_entries; ++i) {

    struct dmsan_full_entry *e1 = &ctx->full_entries1[i];
    struct dmsan_full_entry *e2 = &ctx->full_entries2[i];
    struct dmsan_full_entry *e3 = &ctx->full_entries3[i];

    if (full_entry_empty(e1) && full_entry_empty(e2) && full_entry_empty(e3)) {
      continue;
    }

    if (e1->value != e3->value || !full_identity_equal(e1, e3)) {
      ++ctx->full_nondet_slots;
      continue;
    }

    ++ctx->full_compared_slots;
    if (e1->value != e2->value) {
      if (ctx->first_diff_slot == (u64)-1) { ctx->first_diff_slot = i; }
      ++ctx->full_diff_slots;
    }

  }

  if (ctx->full_diff_slots) { return QDMSAN_DIFF_BUG; }
  if (!ctx->full_compared_slots && ctx->full_nondet_slots) {
    return QDMSAN_DIFF_NONDET;
  }
  return QDMSAN_DIFF_CLEAN;

}

static qdmsan_diff_result_t fast_verdict(qdmsan_diff_ctx_t *ctx) {

  ctx->last_verdict_aux_rescue = 0;
  ctx->candidate_mask = 0;
  ctx->confirmed_mask = 0;
  ctx->nondet_mask = 0;

  if (signatures_equal(&ctx->snap1, &ctx->snap2)) {
    return QDMSAN_DIFF_CLEAN;
  }

  struct qdmsan_plane_verdict planes =
      qdmsan_classify_triplet(&ctx->snap1, &ctx->snap2, &ctx->snap3);
  ctx->candidate_mask = planes.candidate_mask;
  ctx->confirmed_mask = planes.confirmed_mask;
  ctx->nondet_mask = planes.nondet_mask;

  if (!qdmsan_report_triplet_complete(&ctx->snap1, &ctx->snap2,
                                      &ctx->snap3)) {
    return QDMSAN_DIFF_CLEAN;
  }

  if (ctx->confirmed_mask) { return QDMSAN_DIFF_BUG; }
  if (ctx->nondet_mask) { return QDMSAN_DIFF_NONDET; }
  return QDMSAN_DIFF_CLEAN;

}

static qdmsan_diff_result_t confirm_triplet(qdmsan_diff_ctx_t *ctx) {

  struct dmsan_fast_map a, b, c;

  qdmsan_diff_result_t r = run_one(ctx, DMSAN_POISON_RUN1, NULL, NULL);
  if (r != QDMSAN_DIFF_CLEAN) { return r; }
  memcpy(&a, ctx->fast_map, sizeof(a));

  r = run_one(ctx, DMSAN_POISON_RUN1, NULL, NULL);
  if (r != QDMSAN_DIFF_CLEAN) { return r; }
  memcpy(&b, ctx->fast_map, sizeof(b));

  r = run_one(ctx, DMSAN_POISON_RUN2, NULL, NULL);
  if (r != QDMSAN_DIFF_CLEAN) { return r; }
  memcpy(&c, ctx->fast_map, sizeof(c));

  if (!qdmsan_report_triplet_complete(&a, &c, &b)) {
    return QDMSAN_DIFF_CLEAN;
  }

  struct qdmsan_plane_verdict planes = qdmsan_classify_triplet(&a, &c, &b);
  if (planes.confirmed_mask) { return QDMSAN_DIFF_BUG; }
  if (planes.nondet_mask) { return QDMSAN_DIFF_NONDET; }
  return QDMSAN_DIFF_CLEAN;

}

static qdmsan_diff_result_t confirm_aux_triplet(qdmsan_diff_ctx_t *ctx) {

  u16 *a = ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  u16 *b = ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  u16 *c = ck_alloc(sizeof(u16) * DMSAN_SITE_CLASS_ENTRIES);
  qdmsan_diff_result_t verdict = QDMSAN_DIFF_CLEAN;

  qdmsan_diff_result_t r = run_one(ctx, DMSAN_POISON_RUN1, NULL, a);
  if (r != QDMSAN_DIFF_CLEAN) {
    verdict = r;
    goto done;
  }

  r = run_one(ctx, DMSAN_POISON_RUN1, NULL, b);
  if (r != QDMSAN_DIFF_CLEAN) {
    verdict = r;
    goto done;
  }

  r = run_one(ctx, DMSAN_POISON_RUN2, NULL, c);
  if (r != QDMSAN_DIFF_CLEAN) {
    verdict = r;
    goto done;
  }

  /* Confirmation runs are ordered Run1, Run1, Run2; the aux verdict expects
     Run1, Run2, Run3, so the same-poison second run is the Run3 argument. */
  verdict = aux_maps_verdict(a, c, b);

done:
  ck_free(a);
  ck_free(b);
  ck_free(c);
  return verdict;

}

static qdmsan_diff_result_t apply_confirmations(qdmsan_diff_ctx_t *ctx,
                                                qdmsan_diff_result_t verdict) {

  if (verdict != QDMSAN_DIFF_BUG) { return verdict; }
  if (ctx->mode == QDMSAN_DIFF_MODE_FULL) { return verdict; }

  for (u32 i = 0; i < ctx->confirm_runs; ++i) {
    qdmsan_diff_result_t r = ctx->last_verdict_aux_rescue
                                 ? confirm_aux_triplet(ctx)
                                 : confirm_triplet(ctx);
    if (r != QDMSAN_DIFF_BUG) { return r; }
  }

  return QDMSAN_DIFF_BUG;

}

qdmsan_diff_result_t qdmsan_diff_check(qdmsan_diff_ctx_t *ctx) {

  qdmsan_diff_result_t r;
  ctx->candidate_mask = 0;
  ctx->confirmed_mask = 0;
  ctx->nondet_mask = 0;

  r = run_and_save(ctx, 1, DMSAN_POISON_RUN1);
  if (r != QDMSAN_DIFF_CLEAN) { return r; }

  r = run_and_save(ctx, 2, DMSAN_POISON_RUN2);
  if (r != QDMSAN_DIFF_CLEAN) { return r; }

  /* The state oracle needs the repeat run even when the digests agree, since
     its verdict comes from coverage rather than from those digests. */
  if (!ctx->state_oracle && signatures_equal(&ctx->snap1, &ctx->snap2)) {
    return QDMSAN_DIFF_CLEAN;
  }

  r = run_and_save(ctx, 3, DMSAN_POISON_RUN3);
  if (r != QDMSAN_DIFF_CLEAN) { return r; }

  if (ctx->state_oracle) {
    return cov_maps_verdict(ctx, ctx->cov1, ctx->cov2, ctx->cov3);
  }

  /* The three fast-map planes are the online oracle in every mode. Full mode
     additionally populates localization statistics but cannot hide a pure
     OOB/UAF fast-plane finding. */
  if (ctx->mode == QDMSAN_DIFF_MODE_FULL) { (void)full_compare(ctx); }
  qdmsan_diff_result_t verdict = fast_verdict(ctx);
  return apply_confirmations(ctx, verdict);

}

static int elf_bases(const char *target, u64 *exec_load_out, u64 *text_out) {

  int fd = open(target, O_RDONLY);
  if (fd < 0) { return 0; }

  struct stat st;
  if (fstat(fd, &st) || st.st_size <= 0) {
    close(fd);
    return 0;
  }

  size_t size = (size_t)st.st_size;
  u8    *image = malloc(size);
  if (!image) {
    close(fd);
    return 0;
  }

  size_t off = 0;
  while (off < size) {
    ssize_t got = read(fd, image + off, size - off);
    if (got <= 0) {
      free(image);
      close(fd);
      return 0;
    }
    off += (size_t)got;
  }
  close(fd);

  int ok = 0;
  if (size >= EI_NIDENT && image[EI_MAG0] == ELFMAG0 &&
      image[EI_MAG1] == ELFMAG1 && image[EI_MAG2] == ELFMAG2 &&
      image[EI_MAG3] == ELFMAG3) {

    if (image[EI_CLASS] == ELFCLASS64 && size >= sizeof(Elf64_Ehdr)) {
      const Elf64_Ehdr *eh = (const Elf64_Ehdr *)image;
      if (eh->e_phoff &&
          eh->e_phoff + (u64)eh->e_phnum * sizeof(Elf64_Phdr) <= size) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(image + eh->e_phoff);
        for (u16 i = 0; i < eh->e_phnum; ++i) {
          if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X)) {
            if (exec_load_out) { *exec_load_out = ph[i].p_vaddr; }
            ok = 1;
            break;
          }
        }
      }
      if (eh->e_shoff &&
          eh->e_shoff + (u64)eh->e_shnum * sizeof(Elf64_Shdr) <= size &&
          eh->e_shstrndx < eh->e_shnum) {
        const Elf64_Shdr *sh = (const Elf64_Shdr *)(image + eh->e_shoff);
        const Elf64_Shdr *str = &sh[eh->e_shstrndx];
        if (str->sh_offset + str->sh_size <= size) {
          const char *names = (const char *)image + str->sh_offset;
          for (u16 i = 0; i < eh->e_shnum; ++i) {
            if (sh[i].sh_name >= str->sh_size) { continue; }
            if (!strcmp(names + sh[i].sh_name, ".text")) {
              if (text_out) { *text_out = sh[i].sh_addr; }
              ok = 1;
              break;
            }
          }
        }
      }
    } else if (image[EI_CLASS] == ELFCLASS32 && size >= sizeof(Elf32_Ehdr)) {
      const Elf32_Ehdr *eh = (const Elf32_Ehdr *)image;
      if (eh->e_phoff &&
          eh->e_phoff + (u64)eh->e_phnum * sizeof(Elf32_Phdr) <= size) {
        const Elf32_Phdr *ph = (const Elf32_Phdr *)(image + eh->e_phoff);
        for (u16 i = 0; i < eh->e_phnum; ++i) {
          if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X)) {
            if (exec_load_out) { *exec_load_out = ph[i].p_vaddr; }
            ok = 1;
            break;
          }
        }
      }
      if (eh->e_shoff &&
          eh->e_shoff + (u64)eh->e_shnum * sizeof(Elf32_Shdr) <= size &&
          eh->e_shstrndx < eh->e_shnum) {
        const Elf32_Shdr *sh = (const Elf32_Shdr *)(image + eh->e_shoff);
        const Elf32_Shdr *str = &sh[eh->e_shstrndx];
        if (str->sh_offset + str->sh_size <= size) {
          const char *names = (const char *)image + str->sh_offset;
          for (u16 i = 0; i < eh->e_shnum; ++i) {
            if (sh[i].sh_name >= str->sh_size) { continue; }
            if (!strcmp(names + sh[i].sh_name, ".text")) {
              if (text_out) { *text_out = sh[i].sh_addr; }
              ok = 1;
              break;
            }
          }
        }
      }
    }

  }

  free(image);
  return ok;

}

static int resolve_with_tool(const char *tool, const char *target, u64 addr,
                             char *buf, size_t buflen) {

  int fds[2];
  if (pipe(fds)) { return 0; }
  char address[32];
  snprintf(address, sizeof(address), "0x%llx", (unsigned long long)addr);
  pid_t pid = fork();
  if (pid < 0) { close(fds[0]); close(fds[1]); return 0; }
  if (!pid) {
    close(fds[0]);
    if (dup2(fds[1], STDOUT_FILENO) < 0) { _exit(127); }
    close(fds[1]);
    int nullfd = open("/dev/null", O_WRONLY);
    if (nullfd >= 0) { dup2(nullfd, STDERR_FILENO); close(nullfd); }
    char *const args[] = {(char *)tool, "-f", "-C", "-e", (char *)target,
                         address, NULL};
    execvp(tool, args);
    _exit(127);
  }
  close(fds[1]);
  FILE *fp = fdopen(fds[0], "r");
  char func[256] = {0}, loc[512] = {0};
  int parsed = fp && fgets(func, sizeof(func), fp) && fgets(loc, sizeof(loc), fp);
  if (fp) { fclose(fp); } else { close(fds[0]); }
  int status = 0;
  pid_t waited;
  do {
    if (interrupted_signal) { kill(pid, SIGKILL); }
    waited = waitpid(pid, &status, 0);
  } while (waited < 0 && errno == EINTR);
  check_interrupted();
  if (waited != pid || !WIFEXITED(status) || WEXITSTATUS(status) || !parsed) {
    return 0;
  }
  func[strcspn(func, "\r\n")] = '\0';
  loc[strcspn(loc, "\r\n")] = '\0';
  if (func[0] == '?' || loc[0] == '?') { return 0; }
  snprintf(buf, buflen, "%s @ %s", func, loc);
  return 1;

}

static int resolve_addr(const char *target, u64 addr, char *buf, size_t buflen) {

  if (!target || !addr || !buflen) { return 0; }
  return resolve_with_tool("llvm-addr2line", target, addr, buf, buflen) ||
         resolve_with_tool("addr2line", target, addr, buf, buflen);

}

static int resolve_pc(const char *target, u64 pc, char *buf, size_t buflen) {

  if (!target || !pc || !buflen) { return 0; }

  if (resolve_addr(target, pc - 1, buf, buflen)) { return 1; }

  u64 exec_load = 0;
  u64 text = 0;
  if (elf_bases(target, &exec_load, &text)) {
    if (exec_load && resolve_addr(target, exec_load + pc - 1, buf, buflen)) {
      return 1;
    }
    if (resolve_addr(target, text + pc - 1, buf, buflen)) { return 1; }
  }

  return 0;

}

static void report_full_diffs(qdmsan_diff_ctx_t *ctx) {

  if (!ctx->full_map || !ctx->full_diff_slots) { return; }

  printf("  full: compared=%llu nondet=%llu diffs=%llu total=(%llu,%llu,%llu) "
         "overflow=(%llu,%llu,%llu) module_base=0x%llx\n",
         (unsigned long long)ctx->full_compared_slots,
         (unsigned long long)ctx->full_nondet_slots,
         (unsigned long long)ctx->full_diff_slots,
         (unsigned long long)ctx->full_meta1.total_count,
         (unsigned long long)ctx->full_meta2.total_count,
         (unsigned long long)ctx->full_meta3.total_count,
         (unsigned long long)ctx->full_meta1.overflow_count,
         (unsigned long long)ctx->full_meta2.overflow_count,
         (unsigned long long)ctx->full_meta3.overflow_count,
         (unsigned long long)ctx->full_meta1.module_base);

  if (ctx->full_meta1.overflow_count || ctx->full_meta2.overflow_count ||
      ctx->full_meta3.overflow_count) {
    printf("  note: full hash map had collisions; increase AFL_QDMSAN_FULL_SIZE "
           "for lower collision risk\n");
  }

  u32 emitted = 0;
  for (u64 i = 0; i < ctx->full_entries && emitted < ctx->report_limit; ++i) {
    struct dmsan_full_entry *e1 = &ctx->full_entries1[i];
    struct dmsan_full_entry *e2 = &ctx->full_entries2[i];
    struct dmsan_full_entry *e3 = &ctx->full_entries3[i];

    if (full_entry_empty(e1) && full_entry_empty(e2) && full_entry_empty(e3)) {
      continue;
    }
    if (e1->value != e3->value || !full_identity_equal(e1, e3)) { continue; }
    if (e1->value == e2->value) { continue; }

    char sym[768] = {0};
    printf("  diff[%u]: slot=%llu pc=0x%llx site=0x%08x flags=0x%08x "
           "run1=0x%llx run2=0x%llx\n",
           emitted, (unsigned long long)i, (unsigned long long)e1->pc,
           e1->site_id, e1->flags, (unsigned long long)e1->value,
           (unsigned long long)e2->value);
    if (resolve_pc(ctx->target_path, e1->pc, sym, sizeof(sym))) {
      printf("           %s\n", sym);
    }
    ++emitted;
  }

}

void qdmsan_diff_report(qdmsan_diff_ctx_t *ctx,
                        qdmsan_diff_result_t result) {

  if (ctx->quiet) { return; }

  printf("[%s] mode=%s check=%s runs=%llu candidate=%s(0x%02x) "
         "confirmed=%s(0x%02x) nondet=%s(0x%02x) oracle=%s\n",
         qdmsan_diff_result_name(result), qdmsan_diff_mode_name(ctx->mode),
         qdmsan_diff_check_name(ctx->check),
         (unsigned long long)ctx->total_runs,
         plane_mask_name(ctx->candidate_mask), ctx->candidate_mask,
         plane_mask_name(ctx->confirmed_mask), ctx->confirmed_mask,
         plane_mask_name(ctx->nondet_mask), ctx->nondet_mask,
         ctx->state_oracle ? "state" : "consumption");

  if (ctx->verbose || result == QDMSAN_DIFF_BUG ||
      result == QDMSAN_DIFF_NONDET) {
    print_signature("run1", &ctx->snap1);
    print_signature("run2", &ctx->snap2);
    if (!signatures_equal(&ctx->snap1, &ctx->snap2) || ctx->state_oracle ||
        ctx->mode == QDMSAN_DIFF_MODE_FULL) {
      print_signature("run3", &ctx->snap3);
    }
  }

  if (ctx->mode == QDMSAN_DIFF_MODE_FULL) { report_full_diffs(ctx); }

}

static char **build_exec_argv(qdmsan_diff_ctx_t *ctx) {

  char **argv = ck_alloc(sizeof(char *) * (ctx->target_argc + 4));
  int    n = 0;
  argv[n++] = ctx->qemu_path;
  argv[n++] = "--";
  for (int i = 0; i < ctx->target_argc; ++i) { argv[n++] = ctx->target_argv[i]; }
  argv[n] = NULL;
  return argv;

}

static void setup_forkserver(qdmsan_diff_ctx_t *ctx, const char *input_file) {

  afl_fsrv_init(&ctx->fsrv);
  ctx->fsrv_started = 1;
  ctx->trace_bits =
      afl_shm_init(&ctx->afl_shm, MAP_SIZE, 0, DEFAULT_PERMISSION, -1);
  if (!ctx->trace_bits) { PFATAL("AFL shared memory init failed"); }

  ctx->fsrv.trace_bits = ctx->trace_bits;

  if (ctx->state_oracle) {
    ctx->cov1 = ck_alloc(MAP_SIZE);
    ctx->cov2 = ck_alloc(MAP_SIZE);
    ctx->cov3 = ck_alloc(MAP_SIZE);
  }
  ctx->fsrv.map_size = MAP_SIZE;
  ctx->fsrv.real_map_size = MAP_SIZE;
  ctx->fsrv.target_path = (u8 *)ctx->qemu_path;
  ctx->fsrv.qemu_mode = true;
  ctx->fsrv.san_but_not_instrumented = 1;
  ctx->fsrv.init_child_func = qdmsan_exec_child;
  ctx->fsrv.custom_data_ptr = ctx;
  ctx->fsrv.exec_tmout = ctx->timeout_ms;
  ctx->fsrv.init_tmout = ctx->timeout_ms * 4;
  ctx->fsrv.debug = false;

  setup_input(ctx, input_file);
  check_interrupted();
  ctx->exec_argv = build_exec_argv(ctx);

  be_quiet = 1;
  write_replay_input(ctx);
  check_interrupted();
  afl_fsrv_start(&ctx->fsrv, ctx->exec_argv, &ctx->stop_soon, 0);
  check_interrupted();

}

int qdmsan_diff_init(qdmsan_diff_ctx_t *ctx) {

  capture_fixed_values(ctx);
  setup_shm(ctx);
  export_shm_env(ctx);
  return 0;

}

void qdmsan_diff_cleanup(qdmsan_diff_ctx_t *ctx) {

  if (!ctx) { return; }

  if (ctx->fsrv_started) {
    afl_fsrv_deinit(&ctx->fsrv);
    ctx->fsrv_started = 0;
  }

  if (ctx->trace_bits) {
    afl_shm_deinit(&ctx->afl_shm);
    ctx->trace_bits = NULL;
  }

  if (ctx->cov1) { ck_free(ctx->cov1); ctx->cov1 = NULL; }
  if (ctx->cov2) { ck_free(ctx->cov2); ctx->cov2 = NULL; }
  if (ctx->cov3) { ck_free(ctx->cov3); ctx->cov3 = NULL; }

  if (ctx->input_fd >= 0) {
    close(ctx->input_fd);
    ctx->input_fd = -1;
  }
  if (ctx->input_path[0]) {
    unlink(ctx->input_path);
    ctx->input_path[0] = '\0';
  }

  if (ctx->fast_map && ctx->fast_map != (void *)-1) {
    shmdt(ctx->fast_map);
    ctx->fast_map = NULL;
  }
  if (ctx->feedback_map && ctx->feedback_map != (void *)-1) {
    shmdt(ctx->feedback_map);
    ctx->feedback_map = NULL;
  }
  if (ctx->full_map && ctx->full_map != (void *)-1) {
    shmdt(ctx->full_map);
    ctx->full_map = NULL;
  }
  if (ctx->poison_byte && ctx->poison_byte != (void *)-1) {
    shmdt(ctx->poison_byte);
    ctx->poison_byte = NULL;
  }

  if (ctx->shm_fast_id >= 0) {
    shmctl(ctx->shm_fast_id, IPC_RMID, NULL);
    ctx->shm_fast_id = -1;
  }
  if (ctx->shm_feedback_id >= 0) {
    shmctl(ctx->shm_feedback_id, IPC_RMID, NULL);
    ctx->shm_feedback_id = -1;
  }
  if (ctx->shm_full_id >= 0) {
    shmctl(ctx->shm_full_id, IPC_RMID, NULL);
    ctx->shm_full_id = -1;
  }
  if (ctx->shm_poison_id >= 0) {
    shmctl(ctx->shm_poison_id, IPC_RMID, NULL);
    ctx->shm_poison_id = -1;
  }

  if (ctx->owned_target_argv) {
    for (int i = 0; i < ctx->target_argc; ++i) { ck_free(ctx->owned_target_argv[i]); }
    ck_free(ctx->owned_target_argv);
    ctx->owned_target_argv = NULL;
  }

  ck_free(ctx->exec_argv);
  ctx->exec_argv = NULL;
  ck_free(ctx->aux1);
  ck_free(ctx->aux2);
  ck_free(ctx->aux3);
  ck_free(ctx->full_entries1);
  ck_free(ctx->full_entries2);
  ck_free(ctx->full_entries3);
  free(ctx->input_buf);
  free(ctx->qemu_path);
  free(ctx->libqdmsan_path);

}

static qdmsan_diff_mode_t parse_mode(const char *mode) {

  if (!mode || !*mode || str_eq_ci(mode, "fast")) {
    return QDMSAN_DIFF_MODE_FAST;
  }
  if (str_eq_ci(mode, "fast+aux")) { return QDMSAN_DIFF_MODE_FAST_AUX; }
  if (str_eq_ci(mode, "full")) { return QDMSAN_DIFF_MODE_FULL; }
  die_usage("unknown mode '%s' (expected fast|fast+aux|full)", mode);
  return QDMSAN_DIFF_MODE_FAST;

}

static qdmsan_diff_check_t parse_check(const char *check) {

  if (!check || !*check || str_eq_ci(check, "raw")) {
    return QDMSAN_DIFF_CHECK_RAW;
  }
  if (str_eq_ci(check, "result")) {
    return QDMSAN_DIFF_CHECK_RESULT;
  }
  die_usage("unknown check mode '%s' (expected raw|result)", check);
  return QDMSAN_DIFF_CHECK_RAW;

}

int main(int argc, char **argv) {

  static qdmsan_diff_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.input_fd = -1;
  ctx.shm_fast_id = -1;
  ctx.shm_feedback_id = -1;
  ctx.shm_full_id = -1;
  ctx.shm_poison_id = -1;
  ctx.timeout_ms = QDMSAN_DIFF_DEFAULT_TIMEOUT_MS;
  ctx.confirm_runs = 0;
  ctx.report_limit = QDMSAN_DIFF_DEFAULT_REPORT_LIMIT;
  ctx.full_entries = DMSAN_FULL_DEFAULT_SIZE;
  ctx.mode = parse_mode(getenv("AFL_QDMSAN_MODE"));
  ctx.check = parse_check(getenv("AFL_QDMSAN_CHECK"));
  if (getenv("AFL_DMSAN_CONFIRM_RUNS")) {
    ctx.confirm_runs = parse_u32("AFL_DMSAN_CONFIRM_RUNS",
                                 getenv("AFL_DMSAN_CONFIRM_RUNS"), 0, 1000);
  }

  const char *input_file = NULL;

  int opt;
  while ((opt = getopt(argc, argv, "+q:l:m:c:i:t:C:R:SvQh")) != -1) {
    switch (opt) {
      case 'q':
        ctx.qemu_path = xstrdup0(optarg);
        break;
      case 'l':
        ctx.libqdmsan_path = xstrdup0(optarg);
        break;
      case 'm':
        ctx.mode = parse_mode(optarg);
        break;
      case 'c':
        ctx.check = parse_check(optarg);
        break;
      case 'i':
        input_file = optarg;
        break;
      case 't':
        ctx.timeout_ms = parse_u32("-t", optarg, 1, INT_MAX / 4);
        break;
      case 'C':
        ctx.confirm_runs = parse_u32("-C", optarg, 0, 1000);
        break;
      case 'R':
        ctx.report_limit = parse_u32("-R", optarg, 0, UINT32_MAX);
        break;
      case 'S':
        ctx.state_oracle = 1;
        break;
      case 'v':
        ctx.verbose = 1;
        break;
      case 'Q':
        ctx.quiet = 1;
        break;
      case 'h':
        die_usage(NULL);
        break;
      default:
        die_usage(NULL);
    }
  }

  if (optind < argc && !strcmp(argv[optind], "--")) { ++optind; }
  if (optind >= argc) { die_usage("missing target"); }

  ctx.target_argc = argc - optind;
  ctx.target_argv = &argv[optind];
  ctx.target_path = ctx.target_argv[0];

  if (!ctx.qemu_path) { ctx.qemu_path = find_qemu_path(); }
  if (!ctx.qemu_path) {
    die_usage("unable to locate afl-qemu-trace; pass -q <path>");
  }
  if (!file_executable(ctx.qemu_path)) {
    die_usage("qemu path is not executable: %s", ctx.qemu_path);
  }

  if (ctx.libqdmsan_path && access(ctx.libqdmsan_path, R_OK)) {
    die_usage("libqdmsan path is not readable: %s", ctx.libqdmsan_path);
  }
  if (!ctx.libqdmsan_path) { ctx.libqdmsan_path = find_libqdmsan_path(); }
  if (ctx.libqdmsan_path) { prepend_afl_preload(ctx.libqdmsan_path); }

  if (parse_bool_off(getenv("AFL_QDMSAN_STACK"))) {
    if (ctx.verbose) { fprintf(stderr, "qdmsan-diff: stack poisoning disabled\n"); }
  }

  cleanup_ctx = &ctx;
  if (atexit(cleanup_at_exit)) { PFATAL("atexit failed"); }
  struct sigaction action = {0};
  action.sa_handler = signal_cleanup;
  sigemptyset(&action.sa_mask);
  sigaction(SIGINT, &action, NULL);
  sigaction(SIGTERM, &action, NULL);
  signal(SIGPIPE, SIG_IGN);

  if (qdmsan_diff_init(&ctx) != 0) {
    return QDMSAN_DIFF_ERROR;
  }

  setup_forkserver(&ctx, input_file);
  qdmsan_diff_result_t result = qdmsan_diff_check(&ctx);
  qdmsan_diff_report(&ctx, result);
  check_interrupted();
  return (int)result;

}
