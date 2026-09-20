#define _GNU_SOURCE

#include <argp.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <iconv.h>
#include <libintl.h>
#include <linux/capability.h>
#include <pthread.h>
#include <pwd.h>
#include <grp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <regex.h>
#include <resolv.h>
#include <semaphore.h>
#include <signal.h>
#include <spawn.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <time.h>
#include <wchar.h>
#include <wordexp.h>
#include <malloc.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <utmpx.h>
#include <unistd.h>

#define QDMSAN_FAKESYS_NR 0xa2a5
#define QDMSAN_ACTION_PREMAIN 1
#define QDMSAN_ACTION_MAIN_STARTED 2
#define QDMSAN_ACTION_POISON 3
#define QDMSAN_ACTION_SUPPRESS_ENTER 4
#define QDMSAN_ACTION_SUPPRESS_LEAVE 5
#define QDMSAN_ACTION_RECORD 6
#define QDMSAN_ACTION_FIXED_RAND_RAW 7
#define QDMSAN_ACTION_FIXED_RAND_BYTES 8
#define QDMSAN_ACTION_FIXED_TIME_SEC 9
#define QDMSAN_ACTION_FIXED_TIME_USEC 10
#define QDMSAN_ACTION_REGION_ADD 11
#define QDMSAN_ACTION_REGION_REMOVE 12

#define QDMSAN_REGION_REDZONE 1
#define QDMSAN_REGION_FREED 2

#define QDMSAN_HEAP_REDZONE_SIZE 128u
#define QDMSAN_DEFAULT_QUARANTINE_BYTES (64u * 1024u * 1024u)
#define QDMSAN_RETIRED_TOMBSTONES 4096u

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

struct qdmsan_alloc_meta {
  void *ptr;
  void *raw_ptr;
  size_t size;
  size_t raw_size;
  size_t left_redzone_size;
  size_t right_redzone_size;
  unsigned int state;
  struct qdmsan_alloc_meta *next;
  struct qdmsan_alloc_meta *quarantine_next;
};

enum qdmsan_alloc_state {
  QDMSAN_ALLOC_LIVE = 1,
  QDMSAN_ALLOC_QUARANTINED = 2,
  QDMSAN_ALLOC_EVICTING = 3,
  QDMSAN_ALLOC_RETIRED = 4,
};

#define QDMSAN_META_BUCKETS 16384u

struct qdmsan_temp_path {
  char *path;
  int is_dir;
  struct qdmsan_temp_path *next;
};

static void *(*real_malloc)(size_t);
static void (*real_free)(void *);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);
static int (*real_posix_memalign)(void **, size_t, size_t);
static void *(*real_memalign)(size_t, size_t);
static void *(*real_libc_memalign)(size_t, size_t);
static void *(*real_aligned_alloc)(size_t, size_t);
static void *(*real_valloc)(size_t);
static void *(*real_pvalloc)(size_t);
static size_t (*real_malloc_usable_size)(void *);
static char *(*real_strcpy)(char *, const char *);
static char *(*real_strncpy)(char *, const char *, size_t);
static char *(*real_stpcpy)(char *, const char *);
static char *(*real_stpncpy)(char *, const char *, size_t);
static char *(*real_strcat)(char *, const char *);
static char *(*real_strncat)(char *, const char *, size_t);
static wchar_t *(*real_wcscpy)(wchar_t *, const wchar_t *);
static wchar_t *(*real_wcsncpy)(wchar_t *, const wchar_t *, size_t);
static int (*real_memcmp)(const void *, const void *, size_t);
static int (*real_bcmp)(const void *, const void *, size_t);
static int (*real_strcmp)(const char *, const char *);
static int (*real_strncmp)(const char *, const char *, size_t);
static int (*real_strcasecmp)(const char *, const char *);
static int (*real_strncasecmp)(const char *, const char *, size_t);
static size_t (*real_strlen)(const char *);
static size_t (*real_strnlen)(const char *, size_t);
static size_t (*real_wcslen)(const wchar_t *);
static size_t (*real_wcsnlen)(const wchar_t *, size_t);
static void *(*real_memchr)(const void *, int, size_t);
static void *(*real_memrchr)(const void *, int, size_t);
static void *(*real_memmem)(const void *, size_t, const void *, size_t);
static char *(*real_strchr)(const char *, int);
static char *(*real_strrchr)(const char *, int);
static char *(*real_strchrnul)(const char *, int);
static char *(*real_strstr)(const char *, const char *);
static char *(*real_strcasestr)(const char *, const char *);
static char *(*real_strtok)(char *, const char *);
static char *(*real_strptime)(const char *, const char *, struct tm *);
static char *(*real_strpbrk)(const char *, const char *);
static size_t (*real_strspn)(const char *, const char *);
static size_t (*real_strcspn)(const char *, const char *);
static void *(*real_memccpy)(void *, const void *, int, size_t);
static char *(*real_strdup)(const char *);
static char *(*real___strdup)(const char *);
static char *(*real_strndup)(const char *, size_t);
static char *(*real___strndup)(const char *, size_t);
static wchar_t *(*real_wcsdup)(const wchar_t *);
static wchar_t *(*real_wcscat)(wchar_t *, const wchar_t *);
static wchar_t *(*real_wcsncat)(wchar_t *, const wchar_t *, size_t);
static ssize_t (*real_write)(int, const void *, size_t);
static ssize_t (*real_pwrite)(int, const void *, size_t, off_t);
static ssize_t (*real_pwrite64)(int, const void *, size_t, off64_t);
static ssize_t (*real_writev)(int, const struct iovec *, int);
static ssize_t (*real_pwritev)(int, const struct iovec *, int, off_t);
static ssize_t (*real_send)(int, const void *, size_t, int);
static ssize_t (*real_sendto)(int, const void *, size_t, int,
                              const struct sockaddr *, socklen_t);
static ssize_t (*real_sendmsg)(int, const struct msghdr *, int);
static int (*real_open)(const char *, int, ...);
static int (*real_open64)(const char *, int, ...);
static int (*real_openat)(int, const char *, int, ...);
static int (*real_openat64)(int, const char *, int, ...);
static int (*real___open_2)(const char *, int);
static int (*real___open64_2)(const char *, int);
static int (*real___openat_2)(int, const char *, int);
static int (*real___openat64_2)(int, const char *, int);
static int (*real_close)(int);
static int (*real_dup)(int);
static int (*real_dup2)(int, int);
static int (*real_dup3)(int, int, int);
static int (*real_fcntl)(int, int, ...);
static FILE *(*real_fopen)(const char *, const char *);
static FILE *(*real_fopen64)(const char *, const char *);
static FILE *(*real_freopen)(const char *, const char *, FILE *);
static FILE *(*real_freopen64)(const char *, const char *, FILE *);
static int (*real_fclose)(FILE *);
static size_t (*real_fwrite)(const void *, size_t, size_t, FILE *);
static int (*real_fputs)(const char *, FILE *);
static int (*real_puts)(const char *);
static int (*real_mkstemp)(char *);
static int (*real_mkstemps)(char *, int);
static int (*real_mkostemp)(char *, int);
static int (*real_mkostemps)(char *, int, int);
static int (*real_mkstemp64)(char *);
static int (*real_mkstemps64)(char *, int);
static int (*real_mkostemp64)(char *, int);
static int (*real_mkostemps64)(char *, int, int);
static char *(*real_mkdtemp)(char *);
static int (*real_mkdir)(const char *, mode_t);
static int (*real_unlink)(const char *);
static int (*real_unlinkat)(int, const char *, int);
static int (*real_remove)(const char *);
static int (*real_rmdir)(const char *);
static int (*real_rename)(const char *, const char *);
static int (*real_stat)(const char *, struct stat *);
static int (*real_lstat)(const char *, struct stat *);
static int (*real_fstat)(int, struct stat *);
static int (*real___xstat)(int, const char *, struct stat *);
static int (*real___lxstat)(int, const char *, struct stat *);
static int (*real___fxstat)(int, int, struct stat *);
static int (*real_stat64)(const char *, struct stat64 *);
static int (*real_lstat64)(const char *, struct stat64 *);
static int (*real_fstat64)(int, struct stat64 *);
static int (*real___xstat64)(int, const char *, struct stat64 *);
static int (*real___lxstat64)(int, const char *, struct stat64 *);
static int (*real___fxstat64)(int, int, struct stat64 *);
static int (*real_rand)(void);
static void (*real_srand)(unsigned int);
static long (*real_random)(void);
static void (*real_srandom)(unsigned int);
static double (*real_drand48)(void);
static long (*real_lrand48)(void);
static long (*real_mrand48)(void);
static void (*real_srand48)(long);
static unsigned short *(*real_seed48)(unsigned short[3]);
static int (*real_random_r)(struct random_data *, int32_t *);
static int (*real_srandom_r)(unsigned int, struct random_data *);
static int (*real_rand_r)(unsigned int *);
static int (*real_drand48_r)(struct drand48_data *, double *);
static int (*real_lrand48_r)(struct drand48_data *, long *);
static int (*real_mrand48_r)(struct drand48_data *, long *);
static int (*real_srand48_r)(long, struct drand48_data *);
static time_t (*real_time)(time_t *);
static int (*real_gettimeofday)(struct timeval *, void *);
static int (*real_clock_gettime)(clockid_t, struct timespec *);
static int (*real_clock_getres)(clockid_t, struct timespec *);
static int (*real_clock_settime)(clockid_t, const struct timespec *);
static int (*real_ftime)(struct timeb *);
static clock_t (*real_times)(struct tms *);
static clock_t (*real_clock)(void);
static int (*real_getrusage)(int, struct rusage *);
static struct tm *(*real_localtime)(const time_t *);
static struct tm *(*real_localtime_r)(const time_t *, struct tm *);
static struct tm *(*real_gmtime)(const time_t *);
static struct tm *(*real_gmtime_r)(const time_t *, struct tm *);
static char *(*real_ctime)(const time_t *);
static char *(*real_ctime_r)(const time_t *, char *);
static char *(*real_asctime)(const struct tm *);
static char *(*real_asctime_r)(const struct tm *, char *);
static time_t (*real_mktime)(struct tm *);
static ssize_t (*real_getrandom)(void *, size_t, unsigned int);
static int (*real_getentropy)(void *, size_t);
static int (*real_setenv)(const char *, const char *, int);
static char *(*real_textdomain)(const char *);
static int (*real_pthread_setname_np)(pthread_t, const char *);
static int (*real_getaddrinfo)(const char *, const char *,
                               const struct addrinfo *, struct addrinfo **);
static int (*real_getpwnam_r)(const char *, struct passwd *, char *, size_t,
                              struct passwd **);
static struct passwd *(*real_getpwnam)(const char *);
static struct group *(*real_getgrnam)(const char *);
static int (*real_getgrnam_r)(const char *, struct group *, char *, size_t,
                              struct group **);
static FILE *(*real_popen)(const char *, const char *);
static int (*real_posix_spawn)(pid_t *, const char *,
                               const posix_spawn_file_actions_t *,
                               const posix_spawnattr_t *, char *const[],
                               char *const[]);
static int (*real_posix_spawnp)(pid_t *, const char *,
                                const posix_spawn_file_actions_t *,
                                const posix_spawnattr_t *, char *const[],
                                char *const[]);
static size_t (*real_iconv)(iconv_t, char **, size_t *, char **, size_t *);
static size_t (*real_regerror)(int, const regex_t *, char *, size_t);
static int (*real_regcomp)(regex_t *, const char *, int);
static void (*real_regfree)(regex_t *);
static size_t (*real_mbsrtowcs)(wchar_t *, const char **, size_t, mbstate_t *);
static size_t (*real_mbsnrtowcs)(wchar_t *, const char **, size_t, size_t,
                                 mbstate_t *);
static size_t (*real_wcsrtombs)(char *, const wchar_t **, size_t, mbstate_t *);
static size_t (*real_wcsnrtombs)(char *, const wchar_t **, size_t, size_t,
                                 mbstate_t *);
static size_t (*real_wcrtomb)(char *, wchar_t, mbstate_t *);
static int (*real_capget)(cap_user_header_t, cap_user_data_t);
static int (*real_xdr_bytes)(void *, char **, unsigned int *, unsigned int);
static int (*real_xdr_string)(void *, char **, unsigned int);
static void (*real_xdrrec_create)(void *, unsigned int, unsigned int, char *,
                                  int (*)(char *, char *, int),
                                  int (*)(char *, char *, int));
static struct utmpx *(*real_pututxline)(const struct utmpx *);
static error_t (*real_argp_parse)(const struct argp *, int, char **, unsigned,
                                  int *, void *);
static sem_t *(*real_sem_open)(const char *, int, ...);
static int (*real_sem_timedwait)(sem_t *, const struct timespec *);
static int (*real_sem_unlink)(const char *);
static int (*real_sigprocmask)(int, const sigset_t *, sigset_t *);
static int (*real_pthread_sigmask)(int, const sigset_t *, sigset_t *);
static int (*real_sigaction)(int, const struct sigaction *, struct sigaction *);
static int (*real_sigandset)(sigset_t *, const sigset_t *, const sigset_t *);
static int (*real_sigorset)(sigset_t *, const sigset_t *, const sigset_t *);
static int (*real_sigwait)(const sigset_t *, int *);
static int (*real_sigwaitinfo)(const sigset_t *, siginfo_t *);
static int (*real_prctl)(int, ...);
static long (*real_ptrace)(enum __ptrace_request, ...);
static const char *(*real_inet_ntop)(int, const void *, char *, socklen_t);
static int (*real_inet_pton)(int, const char *, void *);
static int (*real_inet_aton)(const char *, struct in_addr *);
static int (*real___b64_ntop)(const unsigned char *, size_t, char *, size_t);
static int (*real___b64_pton)(const char *, unsigned char *, size_t);
static int (*real_wordexp)(const char *, wordexp_t *, int);
static char **(*real_backtrace_symbols)(void *const *, int);
static int (*real_initgroups)(const char *, gid_t);
static char *(*real_ether_ntoa)(const struct ether_addr *);
static struct ether_addr *(*real_ether_aton)(const char *);
static int (*real_ether_ntohost)(char *, const struct ether_addr *);
static int (*real_ether_hostton)(const char *, struct ether_addr *);
static int (*real_ether_line)(const char *, struct ether_addr *, char *);
static char *(*real_ether_ntoa_r)(const struct ether_addr *, char *);
static struct ether_addr *(*real_ether_aton_r)(const char *,
                                               struct ether_addr *);
static unsigned int (*real_if_nametoindex)(const char *);
static FILE *(*real_fdopen)(int, const char *);
static int (*real_getgrouplist)(const char *, gid_t, gid_t *, int *);
static struct protoent *(*real_getprotobyname)(const char *);
static int (*real_getprotobyname_r)(const char *, struct protoent *, char *,
                                    size_t, struct protoent **);
static struct netent *(*real_getnetbyname)(const char *);
static unsigned int (*real_random_device_getval)(void *);
static unsigned int (*real_random_device_getval_pretr1)(void *);
static double (*real_random_device_getentropy)(const void *);
static int (*real_libc_start_main)(int (*)(int, char **, char **), int, char **,
                                   int (*)(int, char **, char **),
                                   void (*)(void), void (*)(void), void *);

static pthread_mutex_t meta_lock = PTHREAD_MUTEX_INITIALIZER;
static struct qdmsan_alloc_meta *meta_buckets[QDMSAN_META_BUCKETS];
static struct qdmsan_alloc_meta *quarantine_head;
static struct qdmsan_alloc_meta *quarantine_tail;
static size_t quarantine_bytes;
static size_t quarantine_limit = QDMSAN_DEFAULT_QUARANTINE_BYTES;
static struct qdmsan_alloc_meta *retired_head;
static struct qdmsan_alloc_meta *retired_tail;
static size_t retired_count;
static pthread_mutex_t temp_lock = PTHREAD_MUTEX_INITIALIZER;
static struct qdmsan_temp_path *temp_head;
static unsigned char temp_fds[4096];
static unsigned int mkstemp_call_count;
static unsigned long clock_call_count;
static __thread int in_qdmsan_hook;
static __thread int in_qdmsan_transfer_hook;
static int qdmsan_check_result_mode = -1;
static int (*saved_main)(int, char **, char **);

static long qdmsan_call(unsigned long action, unsigned long arg1,
                        unsigned long arg2, unsigned long arg3) {
  return syscall(QDMSAN_FAKESYS_NR, action, arg1, arg2, arg3);
}

static void qdmsan_resolve(void) {
  if (real_malloc) return;

  real_malloc = dlsym(RTLD_NEXT, "malloc");
  real_free = dlsym(RTLD_NEXT, "free");
  real_calloc = dlsym(RTLD_NEXT, "calloc");
  real_realloc = dlsym(RTLD_NEXT, "realloc");
  real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
  real_memalign = dlsym(RTLD_NEXT, "memalign");
  real_libc_memalign = dlsym(RTLD_NEXT, "__libc_memalign");
  real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
  real_valloc = dlsym(RTLD_NEXT, "valloc");
  real_pvalloc = dlsym(RTLD_NEXT, "pvalloc");
  real_malloc_usable_size = dlsym(RTLD_NEXT, "malloc_usable_size");
  real_strcpy = dlsym(RTLD_NEXT, "strcpy");
  real_strncpy = dlsym(RTLD_NEXT, "strncpy");
  real_stpcpy = dlsym(RTLD_NEXT, "stpcpy");
  real_stpncpy = dlsym(RTLD_NEXT, "stpncpy");
  real_strcat = dlsym(RTLD_NEXT, "strcat");
  real_strncat = dlsym(RTLD_NEXT, "strncat");
  real_wcscpy = dlsym(RTLD_NEXT, "wcscpy");
  real_wcsncpy = dlsym(RTLD_NEXT, "wcsncpy");
  real_memcmp = dlsym(RTLD_NEXT, "memcmp");
  real_bcmp = dlsym(RTLD_NEXT, "bcmp");
  real_strcmp = dlsym(RTLD_NEXT, "strcmp");
  real_strncmp = dlsym(RTLD_NEXT, "strncmp");
  real_strcasecmp = dlsym(RTLD_NEXT, "strcasecmp");
  real_strncasecmp = dlsym(RTLD_NEXT, "strncasecmp");
  real_strlen = dlsym(RTLD_NEXT, "strlen");
  real_strnlen = dlsym(RTLD_NEXT, "strnlen");
  real_wcslen = dlsym(RTLD_NEXT, "wcslen");
  real_wcsnlen = dlsym(RTLD_NEXT, "wcsnlen");
  real_memchr = dlsym(RTLD_NEXT, "memchr");
  real_memrchr = dlsym(RTLD_NEXT, "memrchr");
  real_memmem = dlsym(RTLD_NEXT, "memmem");
  real_strchr = dlsym(RTLD_NEXT, "strchr");
  real_strrchr = dlsym(RTLD_NEXT, "strrchr");
  real_strchrnul = dlsym(RTLD_NEXT, "strchrnul");
  real_strstr = dlsym(RTLD_NEXT, "strstr");
  real_strcasestr = dlsym(RTLD_NEXT, "strcasestr");
  real_strtok = dlsym(RTLD_NEXT, "strtok");
  real_strptime = dlsym(RTLD_NEXT, "strptime");
  real_strpbrk = dlsym(RTLD_NEXT, "strpbrk");
  real_strspn = dlsym(RTLD_NEXT, "strspn");
  real_strcspn = dlsym(RTLD_NEXT, "strcspn");
  real_memccpy = dlsym(RTLD_NEXT, "memccpy");
  real_strdup = dlsym(RTLD_NEXT, "strdup");
  real___strdup = dlsym(RTLD_NEXT, "__strdup");
  real_strndup = dlsym(RTLD_NEXT, "strndup");
  real___strndup = dlsym(RTLD_NEXT, "__strndup");
  real_wcsdup = dlsym(RTLD_NEXT, "wcsdup");
  real_wcscat = dlsym(RTLD_NEXT, "wcscat");
  real_wcsncat = dlsym(RTLD_NEXT, "wcsncat");
  real_write = dlsym(RTLD_NEXT, "write");
  real_pwrite = dlsym(RTLD_NEXT, "pwrite");
  real_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");
  real_writev = dlsym(RTLD_NEXT, "writev");
  real_pwritev = dlsym(RTLD_NEXT, "pwritev");
  real_send = dlsym(RTLD_NEXT, "send");
  real_sendto = dlsym(RTLD_NEXT, "sendto");
  real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
  real_open = dlsym(RTLD_NEXT, "open");
  real_open64 = dlsym(RTLD_NEXT, "open64");
  real_openat = dlsym(RTLD_NEXT, "openat");
  real_openat64 = dlsym(RTLD_NEXT, "openat64");
  real___open_2 = dlsym(RTLD_NEXT, "__open_2");
  real___open64_2 = dlsym(RTLD_NEXT, "__open64_2");
  real___openat_2 = dlsym(RTLD_NEXT, "__openat_2");
  real___openat64_2 = dlsym(RTLD_NEXT, "__openat64_2");
  real_close = dlsym(RTLD_NEXT, "close");
  real_dup = dlsym(RTLD_NEXT, "dup");
  real_dup2 = dlsym(RTLD_NEXT, "dup2");
  real_dup3 = dlsym(RTLD_NEXT, "dup3");
  real_fcntl = dlsym(RTLD_NEXT, "fcntl");
  real_fopen = dlsym(RTLD_NEXT, "fopen");
  real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
  real_freopen = dlsym(RTLD_NEXT, "freopen");
  real_freopen64 = dlsym(RTLD_NEXT, "freopen64");
  real_fclose = dlsym(RTLD_NEXT, "fclose");
  real_fwrite = dlsym(RTLD_NEXT, "fwrite");
  real_fputs = dlsym(RTLD_NEXT, "fputs");
  real_puts = dlsym(RTLD_NEXT, "puts");
  real_mkstemp = dlsym(RTLD_NEXT, "mkstemp");
  real_mkstemps = dlsym(RTLD_NEXT, "mkstemps");
  real_mkostemp = dlsym(RTLD_NEXT, "mkostemp");
  real_mkostemps = dlsym(RTLD_NEXT, "mkostemps");
  real_mkstemp64 = dlsym(RTLD_NEXT, "mkstemp64");
  real_mkstemps64 = dlsym(RTLD_NEXT, "mkstemps64");
  real_mkostemp64 = dlsym(RTLD_NEXT, "mkostemp64");
  real_mkostemps64 = dlsym(RTLD_NEXT, "mkostemps64");
  real_mkdtemp = dlsym(RTLD_NEXT, "mkdtemp");
  real_mkdir = dlsym(RTLD_NEXT, "mkdir");
  real_unlink = dlsym(RTLD_NEXT, "unlink");
  real_unlinkat = dlsym(RTLD_NEXT, "unlinkat");
  real_remove = dlsym(RTLD_NEXT, "remove");
  real_rmdir = dlsym(RTLD_NEXT, "rmdir");
  real_rename = dlsym(RTLD_NEXT, "rename");
  real_stat = dlsym(RTLD_NEXT, "stat");
  real_lstat = dlsym(RTLD_NEXT, "lstat");
  real_fstat = dlsym(RTLD_NEXT, "fstat");
  real___xstat = dlsym(RTLD_NEXT, "__xstat");
  real___lxstat = dlsym(RTLD_NEXT, "__lxstat");
  real___fxstat = dlsym(RTLD_NEXT, "__fxstat");
  real_stat64 = dlsym(RTLD_NEXT, "stat64");
  real_lstat64 = dlsym(RTLD_NEXT, "lstat64");
  real_fstat64 = dlsym(RTLD_NEXT, "fstat64");
  real___xstat64 = dlsym(RTLD_NEXT, "__xstat64");
  real___lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");
  real___fxstat64 = dlsym(RTLD_NEXT, "__fxstat64");
  real_rand = dlsym(RTLD_NEXT, "rand");
  real_srand = dlsym(RTLD_NEXT, "srand");
  real_random = dlsym(RTLD_NEXT, "random");
  real_srandom = dlsym(RTLD_NEXT, "srandom");
  real_drand48 = dlsym(RTLD_NEXT, "drand48");
  real_lrand48 = dlsym(RTLD_NEXT, "lrand48");
  real_mrand48 = dlsym(RTLD_NEXT, "mrand48");
  real_srand48 = dlsym(RTLD_NEXT, "srand48");
  real_seed48 = dlsym(RTLD_NEXT, "seed48");
  real_random_r = dlsym(RTLD_NEXT, "random_r");
  real_srandom_r = dlsym(RTLD_NEXT, "srandom_r");
  real_rand_r = dlsym(RTLD_NEXT, "rand_r");
  real_drand48_r = dlsym(RTLD_NEXT, "drand48_r");
  real_lrand48_r = dlsym(RTLD_NEXT, "lrand48_r");
  real_mrand48_r = dlsym(RTLD_NEXT, "mrand48_r");
  real_srand48_r = dlsym(RTLD_NEXT, "srand48_r");
  real_time = dlsym(RTLD_NEXT, "time");
  real_gettimeofday = dlsym(RTLD_NEXT, "gettimeofday");
  real_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");
  real_clock_getres = dlsym(RTLD_NEXT, "clock_getres");
  real_clock_settime = dlsym(RTLD_NEXT, "clock_settime");
  real_ftime = dlsym(RTLD_NEXT, "ftime");
  real_times = dlsym(RTLD_NEXT, "times");
  real_clock = dlsym(RTLD_NEXT, "clock");
  real_getrusage = dlsym(RTLD_NEXT, "getrusage");
  real_localtime = dlsym(RTLD_NEXT, "localtime");
  real_localtime_r = dlsym(RTLD_NEXT, "localtime_r");
  real_gmtime = dlsym(RTLD_NEXT, "gmtime");
  real_gmtime_r = dlsym(RTLD_NEXT, "gmtime_r");
  real_ctime = dlsym(RTLD_NEXT, "ctime");
  real_ctime_r = dlsym(RTLD_NEXT, "ctime_r");
  real_asctime = dlsym(RTLD_NEXT, "asctime");
  real_asctime_r = dlsym(RTLD_NEXT, "asctime_r");
  real_mktime = dlsym(RTLD_NEXT, "mktime");
  real_getrandom = dlsym(RTLD_NEXT, "getrandom");
  real_getentropy = dlsym(RTLD_NEXT, "getentropy");
  real_setenv = dlsym(RTLD_NEXT, "setenv");
  real_textdomain = dlsym(RTLD_NEXT, "textdomain");
  real_pthread_setname_np = dlsym(RTLD_NEXT, "pthread_setname_np");
  real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
  real_getpwnam_r = dlsym(RTLD_NEXT, "getpwnam_r");
  real_getpwnam = dlsym(RTLD_NEXT, "getpwnam");
  real_getgrnam = dlsym(RTLD_NEXT, "getgrnam");
  real_getgrnam_r = dlsym(RTLD_NEXT, "getgrnam_r");
  real_popen = dlsym(RTLD_NEXT, "popen");
  real_posix_spawn = dlsym(RTLD_NEXT, "posix_spawn");
  real_posix_spawnp = dlsym(RTLD_NEXT, "posix_spawnp");
  real_iconv = dlsym(RTLD_NEXT, "iconv");
  real_regerror = dlsym(RTLD_NEXT, "regerror");
  real_regcomp = dlsym(RTLD_NEXT, "regcomp");
  real_regfree = dlsym(RTLD_NEXT, "regfree");
  real_mbsrtowcs = dlsym(RTLD_NEXT, "mbsrtowcs");
  real_mbsnrtowcs = dlsym(RTLD_NEXT, "mbsnrtowcs");
  real_wcsrtombs = dlsym(RTLD_NEXT, "wcsrtombs");
  real_wcsnrtombs = dlsym(RTLD_NEXT, "wcsnrtombs");
  real_wcrtomb = dlsym(RTLD_NEXT, "wcrtomb");
  real_capget = dlsym(RTLD_NEXT, "capget");
  real_xdr_bytes = dlsym(RTLD_NEXT, "xdr_bytes");
  real_xdr_string = dlsym(RTLD_NEXT, "xdr_string");
  real_xdrrec_create = dlsym(RTLD_NEXT, "xdrrec_create");
  real_pututxline = dlsym(RTLD_NEXT, "pututxline");
  real_argp_parse = dlsym(RTLD_NEXT, "argp_parse");
  real_sem_open = dlsym(RTLD_NEXT, "sem_open");
  real_sem_timedwait = dlsym(RTLD_NEXT, "sem_timedwait");
  real_sem_unlink = dlsym(RTLD_NEXT, "sem_unlink");
  real_sigprocmask = dlsym(RTLD_NEXT, "sigprocmask");
  real_pthread_sigmask = dlsym(RTLD_NEXT, "pthread_sigmask");
  real_sigaction = dlsym(RTLD_NEXT, "sigaction");
  real_sigandset = dlsym(RTLD_NEXT, "sigandset");
  real_sigorset = dlsym(RTLD_NEXT, "sigorset");
  real_sigwait = dlsym(RTLD_NEXT, "sigwait");
  real_sigwaitinfo = dlsym(RTLD_NEXT, "sigwaitinfo");
  real_prctl = dlsym(RTLD_NEXT, "prctl");
  real_ptrace = dlsym(RTLD_NEXT, "ptrace");
  real_inet_ntop = dlsym(RTLD_NEXT, "inet_ntop");
  real_inet_pton = dlsym(RTLD_NEXT, "inet_pton");
  real_inet_aton = dlsym(RTLD_NEXT, "inet_aton");
  real___b64_ntop = dlsym(RTLD_NEXT, "__b64_ntop");
  real___b64_pton = dlsym(RTLD_NEXT, "__b64_pton");
  real_wordexp = dlsym(RTLD_NEXT, "wordexp");
  real_backtrace_symbols = dlsym(RTLD_NEXT, "backtrace_symbols");
  real_initgroups = dlsym(RTLD_NEXT, "initgroups");
  real_ether_ntoa = dlsym(RTLD_NEXT, "ether_ntoa");
  real_ether_aton = dlsym(RTLD_NEXT, "ether_aton");
  real_ether_ntohost = dlsym(RTLD_NEXT, "ether_ntohost");
  real_ether_hostton = dlsym(RTLD_NEXT, "ether_hostton");
  real_ether_line = dlsym(RTLD_NEXT, "ether_line");
  real_ether_ntoa_r = dlsym(RTLD_NEXT, "ether_ntoa_r");
  real_ether_aton_r = dlsym(RTLD_NEXT, "ether_aton_r");
  real_if_nametoindex = dlsym(RTLD_NEXT, "if_nametoindex");
  real_fdopen = dlsym(RTLD_NEXT, "fdopen");
  real_getgrouplist = dlsym(RTLD_NEXT, "getgrouplist");
  real_getprotobyname = dlsym(RTLD_NEXT, "getprotobyname");
  real_getprotobyname_r = dlsym(RTLD_NEXT, "getprotobyname_r");
  real_getnetbyname = dlsym(RTLD_NEXT, "getnetbyname");
  real_random_device_getval = dlsym(RTLD_NEXT, "_ZNSt13random_device9_M_getvalEv");
  real_random_device_getval_pretr1 =
      dlsym(RTLD_NEXT, "_ZNSt13random_device16_M_getval_pretr1Ev");
  real_random_device_getentropy =
      dlsym(RTLD_NEXT, "_ZNKSt13random_device13_M_getentropyEv");
  real_libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
}

static size_t qdmsan_meta_bucket(void *ptr) {
  uint64_t x = (uint64_t)(uintptr_t)ptr >> 4;
  x ^= x >> 33;
  x *= UINT64_C(0xff51afd7ed558ccd);
  x ^= x >> 33;
  return (size_t)(x & (QDMSAN_META_BUCKETS - 1));
}

static struct qdmsan_alloc_meta *qdmsan_find_meta(
    void *ptr, struct qdmsan_alloc_meta ***pprev) {
  struct qdmsan_alloc_meta **prev = &meta_buckets[qdmsan_meta_bucket(ptr)];
  struct qdmsan_alloc_meta *cur = *prev;

  while (cur) {
    if (cur->ptr == ptr) {
      if (pprev) *pprev = prev;
      return cur;
    }
    prev = &cur->next;
    cur = cur->next;
  }
  if (pprev) *pprev = prev;
  return NULL;
}

static void qdmsan_insert_meta_locked(struct qdmsan_alloc_meta *meta) {
  struct qdmsan_alloc_meta **slot =
      &meta_buckets[qdmsan_meta_bucket(meta->ptr)];
  meta->next = *slot;
  *slot = meta;
}

static void qdmsan_remove_meta_locked(struct qdmsan_alloc_meta *meta) {
  struct qdmsan_alloc_meta **prev = NULL;
  struct qdmsan_alloc_meta *found = qdmsan_find_meta(meta->ptr, &prev);
  if (found == meta) *prev = meta->next;
  meta->next = NULL;
}

static void qdmsan_unlink_retired_locked(struct qdmsan_alloc_meta *meta) {
  struct qdmsan_alloc_meta *prev = NULL;
  struct qdmsan_alloc_meta *cur = retired_head;
  while (cur && cur != meta) {
    prev = cur;
    cur = cur->quarantine_next;
  }
  if (!cur) return;
  if (prev) {
    prev->quarantine_next = cur->quarantine_next;
  } else {
    retired_head = cur->quarantine_next;
  }
  if (retired_tail == cur) retired_tail = prev;
  cur->quarantine_next = NULL;
  if (retired_count) --retired_count;
}

static void qdmsan_discard_retired_locked(struct qdmsan_alloc_meta *meta) {
  qdmsan_unlink_retired_locked(meta);
  qdmsan_remove_meta_locked(meta);
  real_free(meta);
}

/* Return 1 for a live managed allocation, -1 for a known non-live pointer,
   and 0 for a pointer not owned by this interposer. */
static int qdmsan_managed_size(void *ptr, size_t *size_out) {
  int result = 0;
  if (!ptr) return 0;

  pthread_mutex_lock(&meta_lock);
  struct qdmsan_alloc_meta *meta = qdmsan_find_meta(ptr, NULL);
  if (meta) {
    result = meta->state == QDMSAN_ALLOC_LIVE ? 1 : -1;
    if (size_out) *size_out = meta->size;
  }
  pthread_mutex_unlock(&meta_lock);
  return result;
}

static void qdmsan_poison(void *ptr, size_t size) {
  if (!ptr || !size) return;
  qdmsan_call(QDMSAN_ACTION_POISON, (unsigned long)ptr, (unsigned long)size, 0);
}

static void qdmsan_region_add(void *ptr, size_t size, unsigned long type) {
  if (!ptr || !size) return;
  qdmsan_call(QDMSAN_ACTION_REGION_ADD, (unsigned long)ptr,
              (unsigned long)size, type);
}

static void qdmsan_region_remove(void *ptr, size_t size,
                                 unsigned long type) {
  if (!ptr || !size) return;
  qdmsan_call(QDMSAN_ACTION_REGION_REMOVE, (unsigned long)ptr,
              (unsigned long)size, type);
}

static int qdmsan_valid_alignment(size_t alignment) {
  return alignment && !(alignment & (alignment - 1));
}

static void *qdmsan_allocate_managed(size_t size, size_t alignment,
                                     int zero_payload) {
  size_t storage_size = size ? size : 1;
  size_t overhead;
  size_t raw_size;

  if (alignment < __alignof__(max_align_t)) {
    alignment = __alignof__(max_align_t);
  }
  if (!qdmsan_valid_alignment(alignment) ||
      alignment - 1 > SIZE_MAX - 2 * QDMSAN_HEAP_REDZONE_SIZE) {
    errno = ENOMEM;
    return NULL;
  }
  overhead = 2 * QDMSAN_HEAP_REDZONE_SIZE + alignment - 1;
  if (storage_size > SIZE_MAX - overhead) {
    errno = ENOMEM;
    return NULL;
  }
  raw_size = storage_size + overhead;

  void *raw_ptr = real_malloc(raw_size);
  if (!raw_ptr) return NULL;

  uintptr_t candidate = (uintptr_t)raw_ptr + QDMSAN_HEAP_REDZONE_SIZE;
  if (candidate > UINTPTR_MAX - (alignment - 1)) {
    real_free(raw_ptr);
    errno = ENOMEM;
    return NULL;
  }
  uintptr_t aligned = (candidate + alignment - 1) & ~(uintptr_t)(alignment - 1);
  void *user_ptr = (void *)aligned;

  struct qdmsan_alloc_meta *meta = real_malloc(sizeof(*meta));
  if (!meta) {
    real_free(raw_ptr);
    errno = ENOMEM;
    return NULL;
  }

  meta->ptr = user_ptr;
  meta->raw_ptr = raw_ptr;
  meta->size = size;
  meta->raw_size = raw_size;
  meta->left_redzone_size = (size_t)(aligned - (uintptr_t)raw_ptr);
  meta->right_redzone_size =
      raw_size - meta->left_redzone_size - size;
  meta->state = QDMSAN_ALLOC_LIVE;
  meta->next = NULL;
  meta->quarantine_next = NULL;

  pthread_mutex_lock(&meta_lock);
  struct qdmsan_alloc_meta *existing = qdmsan_find_meta(user_ptr, NULL);
  if (existing && existing->state == QDMSAN_ALLOC_RETIRED) {
    qdmsan_discard_retired_locked(existing);
    existing = NULL;
  }
  if (existing) {
    pthread_mutex_unlock(&meta_lock);
    real_free(meta);
    real_free(raw_ptr);
    errno = ENOMEM;
    return NULL;
  }
  qdmsan_insert_meta_locked(meta);
  pthread_mutex_unlock(&meta_lock);

  /* A single selector fills all three vulnerability domains.  Region
     registration only routes observations; it is not a validity oracle. */
  qdmsan_poison(raw_ptr, raw_size);
  /* Fill the live payload independently of its redzones and alignment.
     QEMU chooses the table offset from this user address and size. */
  qdmsan_poison(user_ptr, size);
  if (zero_payload && size) memset(user_ptr, 0, size);
  qdmsan_region_add(raw_ptr, meta->left_redzone_size, QDMSAN_REGION_REDZONE);
  qdmsan_region_add((char *)user_ptr + size, meta->right_redzone_size,
                    QDMSAN_REGION_REDZONE);
  return user_ptr;
}

static void qdmsan_evict_meta(struct qdmsan_alloc_meta *meta) {
  qdmsan_region_remove(meta->raw_ptr, meta->raw_size, QDMSAN_REGION_FREED);

  /* Keep a bounded set of retired pointer tombstones after releasing raw
     storage.  This catches an immediate double-free even when quarantine is
     configured to 0 MiB, without retaining the object bytes indefinitely. */
  pthread_mutex_lock(&meta_lock);
  real_free(meta->raw_ptr);
  meta->raw_ptr = NULL;
  meta->raw_size = 0;
  meta->left_redzone_size = 0;
  meta->right_redzone_size = 0;
  meta->size = 0;
  meta->state = QDMSAN_ALLOC_RETIRED;
  meta->quarantine_next = NULL;
  if (retired_tail) {
    retired_tail->quarantine_next = meta;
  } else {
    retired_head = meta;
  }
  retired_tail = meta;
  ++retired_count;

  while (retired_count > QDMSAN_RETIRED_TOMBSTONES) {
    struct qdmsan_alloc_meta *retired = retired_head;
    retired_head = retired->quarantine_next;
    if (!retired_head) retired_tail = NULL;
    retired->quarantine_next = NULL;
    --retired_count;
    qdmsan_remove_meta_locked(retired);
    real_free(retired);
  }
  pthread_mutex_unlock(&meta_lock);
}

/* Move a live managed object into the bounded FIFO quarantine.  Return 1 for
   every pointer known to the interposer (including a repeated free), and 0
   for a genuinely foreign pointer that must be forwarded to libc. */
static int qdmsan_quarantine_managed(void *ptr) {
  if (!ptr) return 1;

  struct qdmsan_alloc_meta *evict_list = NULL;
  struct qdmsan_alloc_meta *meta;

  pthread_mutex_lock(&meta_lock);
  meta = qdmsan_find_meta(ptr, NULL);
  if (!meta) {
    pthread_mutex_unlock(&meta_lock);
    return 0;
  }
  if (meta->state != QDMSAN_ALLOC_LIVE) {
    pthread_mutex_unlock(&meta_lock);
    return 1;
  }

  /* Complete the REDZONE -> FREED registry transition while holding the
     allocator lock.  Only then can another thread select this object for
     eviction; otherwise an immediate/zero-sized quarantine could free meta
     while this thread is still publishing the transition. */
  qdmsan_region_remove(meta->raw_ptr, meta->left_redzone_size,
                       QDMSAN_REGION_REDZONE);
  qdmsan_region_remove((char *)meta->ptr + meta->size,
                       meta->right_redzone_size, QDMSAN_REGION_REDZONE);
  qdmsan_poison(meta->raw_ptr, meta->raw_size);
  qdmsan_region_add(meta->raw_ptr, meta->raw_size, QDMSAN_REGION_FREED);

  meta->state = QDMSAN_ALLOC_QUARANTINED;
  meta->quarantine_next = NULL;
  if (quarantine_tail) {
    quarantine_tail->quarantine_next = meta;
  } else {
    quarantine_head = meta;
  }
  quarantine_tail = meta;
  if (meta->raw_size > SIZE_MAX - quarantine_bytes) {
    quarantine_bytes = SIZE_MAX;
  } else {
    quarantine_bytes += meta->raw_size;
  }

  while (quarantine_head && quarantine_bytes > quarantine_limit) {
    struct qdmsan_alloc_meta *evict = quarantine_head;
    quarantine_head = evict->quarantine_next;
    if (!quarantine_head) quarantine_tail = NULL;
    quarantine_bytes = quarantine_bytes >= evict->raw_size
                           ? quarantine_bytes - evict->raw_size
                           : 0;
    evict->state = QDMSAN_ALLOC_EVICTING;
    evict->quarantine_next = evict_list;
    evict_list = evict;
  }
  if (!quarantine_head) quarantine_bytes = 0;
  pthread_mutex_unlock(&meta_lock);

  while (evict_list) {
    struct qdmsan_alloc_meta *next = evict_list->quarantine_next;
    qdmsan_evict_meta(evict_list);
    evict_list = next;
  }
  return 1;
}

static void qdmsan_suppress_enter(void) {
  qdmsan_call(QDMSAN_ACTION_SUPPRESS_ENTER, 0, 0, 0);
}

static void qdmsan_suppress_leave(void) {
  qdmsan_call(QDMSAN_ACTION_SUPPRESS_LEAVE, 0, 0, 0);
}

static void qdmsan_record_libc(unsigned long pc, unsigned long value,
                               unsigned long kind) {
  qdmsan_call(QDMSAN_ACTION_RECORD, pc, value, kind);
}

static int qdmsan_ascii_lower(int c) {
  return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static int qdmsan_mode_is_result_string(const char *s) {
  static const char result[] = "result";
  if (!s) return 0;
  for (size_t i = 0; result[i]; ++i) {
    if (qdmsan_ascii_lower((unsigned char)s[i]) != result[i]) return 0;
  }
  return s[sizeof(result) - 1] == '\0';
}

static int qdmsan_result_mode(void) {
  if (qdmsan_check_result_mode < 0) {
    const char *mode = getenv("AFL_QDMSAN_CHECK");
    if (!mode) mode = getenv("QDMSAN_CHECK_MODE");
    qdmsan_check_result_mode = qdmsan_mode_is_result_string(mode);
  }
  return qdmsan_check_result_mode;
}

static int qdmsan_env_enabled(const char *name) {
  const char *value = getenv(name);
  if (!value || !*value) return 0;
  if (!strcmp(value, "0") || !strcmp(value, "off") ||
      !strcmp(value, "false") || !strcmp(value, "FALSE")) {
    return 0;
  }
  return 1;
}

static int qdmsan_compat_stubs_enabled(void) {
  static int cached = -1;
  if (cached < 0) cached = qdmsan_env_enabled("AFL_QDMSAN_COMPAT_STUBS");
  return cached;
}

static int qdmsan_probably_user_pointer(uintptr_t value) {
  if (!value) return 1;
  if (value < 4096) return 0;
#if UINTPTR_MAX > UINT32_MAX
  uintptr_t top = value >> 47;
  if (top != 0 && top != UINTPTR_MAX >> 47) return 0;
#endif
  return 1;
}

static size_t qdmsan_memcmp_used(const void *s1, const void *s2, size_t n) {
  if (!s1 || !s2) return 0;
  if (!qdmsan_probably_user_pointer((uintptr_t)s1) ||
      !qdmsan_probably_user_pointer((uintptr_t)s2)) {
    return 0;
  }
  const unsigned char *p1 = (const unsigned char *)s1;
  const unsigned char *p2 = (const unsigned char *)s2;
  size_t limit = n < 256 ? n : 256;
  for (size_t i = 0; i < limit; ++i) {
    if (p1[i] != p2[i]) return i + 1;
  }
  return limit;
}

static size_t qdmsan_strcmp_used(const char *s1, const char *s2, size_t max_len,
                                 int case_fold) {
  if (!s1 || !s2) return 0;
  if (!qdmsan_probably_user_pointer((uintptr_t)s1) ||
      !qdmsan_probably_user_pointer((uintptr_t)s2)) {
    return 0;
  }
  size_t limit = max_len < 256 ? max_len : 256;
  for (size_t i = 0; i < limit; ++i) {
    unsigned char c1 = (unsigned char)s1[i];
    unsigned char c2 = (unsigned char)s2[i];
    unsigned char v1 = case_fold ? (unsigned char)qdmsan_ascii_lower(c1) : c1;
    unsigned char v2 = case_fold ? (unsigned char)qdmsan_ascii_lower(c2) : c2;
    if (v1 != v2 || c1 == '\0' || c2 == '\0') return i + 1;
  }
  return limit;
}

static size_t qdmsan_cstr_scan_used(const char *s, size_t max_len) {
  if (!s) return 0;
  if (!qdmsan_probably_user_pointer((uintptr_t)s)) return 0;
  size_t limit = max_len < 256 ? max_len : 256;
  for (size_t i = 0; i < limit; ++i) {
    if (s[i] == '\0') return i + 1;
  }
  return limit;
}

static size_t qdmsan_wcs_scan_used(const wchar_t *s, size_t max_len) {
  if (!s) return 0;
  if (!qdmsan_probably_user_pointer((uintptr_t)s)) return 0;
  size_t limit = max_len < 64 ? max_len : 64;
  for (size_t i = 0; i < limit; ++i) {
    if (s[i] == L'\0') return i + 1;
  }
  return limit;
}

static size_t qdmsan_cstr_observed_len(const char *s, size_t used) {
  if (!s || !used) return 0;
  return s[used - 1] == '\0' ? used - 1 : used;
}

static size_t qdmsan_wcs_observed_len(const wchar_t *s, size_t used) {
  if (!s || !used) return 0;
  return s[used - 1] == L'\0' ? used - 1 : used;
}

static uint64_t qdmsan_fallback_rand_raw(void) {
  static uint64_t fallback_counter;
  uint64_t n = __sync_fetch_and_add(&fallback_counter, 1);
  return UINT64_C(0x123456789abcdef0) + n;
}

static uint64_t qdmsan_fixed_rand_raw(void) {
  uint64_t x = 0;
  if (qdmsan_call(QDMSAN_ACTION_FIXED_RAND_RAW, (unsigned long)&x,
                  (unsigned long)sizeof(x), 0) == 0) {
    return x;
  }
  return qdmsan_fallback_rand_raw();
}

static int qdmsan_fixed_rand_bytes(void *buf, size_t len) {
  if (!buf && len) {
    errno = EFAULT;
    return -1;
  }
  if (!len) return 0;
  if (qdmsan_call(QDMSAN_ACTION_FIXED_RAND_BYTES, (unsigned long)buf,
                  (unsigned long)len, 0) == 0) {
    return 0;
  }
  return -1;
}

static time_t qdmsan_fixed_time_sec(void) {
  long ret = qdmsan_call(QDMSAN_ACTION_FIXED_TIME_SEC, 0, 0, 0);
  if (ret >= 0) return (time_t)ret;
  return (time_t)0;
}

static suseconds_t qdmsan_fixed_time_usec(void) {
  long ret = qdmsan_call(QDMSAN_ACTION_FIXED_TIME_USEC, 0, 0, 0);
  if (ret >= 0) return (suseconds_t)ret;
  return (suseconds_t)0;
}

static uint64_t qdmsan_hash_bytes(const void *ptr, size_t len) {
  if (!ptr) return UINT64_C(0);
  if (!qdmsan_probably_user_pointer((uintptr_t)ptr)) return UINT64_C(0);
  const unsigned char *p = (const unsigned char *)ptr;
  size_t limit = len < 256 ? len : 256;
  uint64_t h = UINT64_C(1469598103934665603) ^ (uint64_t)len;
  for (size_t i = 0; i < limit; ++i) {
    h ^= (uint64_t)p[i];
    h *= UINT64_C(1099511628211);
  }
  return h;
}

static uint64_t qdmsan_hash_cstr(const char *ptr, size_t max_len) {
  if (!ptr) return UINT64_C(0);
  if (!qdmsan_probably_user_pointer((uintptr_t)ptr)) return UINT64_C(0);
  const unsigned char *p = (const unsigned char *)ptr;
  size_t limit = max_len < 256 ? max_len : 256;
  uint64_t h = UINT64_C(1469598103934665603) ^ (uint64_t)max_len;
  for (size_t i = 0; i < limit; ++i) {
    unsigned char c = p[i];
    h ^= (uint64_t)c;
    h *= UINT64_C(1099511628211);
    if (!c) break;
  }
  return h;
}

static uint64_t qdmsan_hash_wcs(const wchar_t *ptr, size_t max_len) {
  if (!ptr) return UINT64_C(0);
  size_t limit = max_len < 64 ? max_len : 64;
  uint64_t h = UINT64_C(1469598103934665603) ^ (uint64_t)max_len;
  for (size_t i = 0; i < limit; ++i) {
    wchar_t c = ptr[i];
    const unsigned char *p = (const unsigned char *)&c;
    for (size_t j = 0; j < sizeof(c); ++j) {
      h ^= (uint64_t)p[j];
      h *= UINT64_C(1099511628211);
    }
    if (!c) break;
  }
  return h;
}

static uint64_t qdmsan_mix64(uint64_t x) {
  x += UINT64_C(0x9e3779b97f4a7c15);
  x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
  return x ^ (x >> 31);
}

static char *qdmsan_real_strdup(const char *s) {
  if (!s) return NULL;
  qdmsan_resolve();
  size_t len = strlen(s) + 1;
  char *out = real_malloc ? real_malloc(len) : malloc(len);
  if (out) memcpy(out, s, len);
  return out;
}

static int qdmsan_path_under_dir(const char *path, const char *dir) {
  if (!path || !dir) return 0;
  size_t len = strlen(dir);
  return len && !strncmp(path, dir, len) && path[len] == '/';
}

static void qdmsan_remember_temp_path(const char *path, int is_dir) {
  if (!path || !*path) return;
  char *copy = qdmsan_real_strdup(path);
  if (!copy) return;

  pthread_mutex_lock(&temp_lock);
  for (struct qdmsan_temp_path *cur = temp_head; cur; cur = cur->next) {
    if (!strcmp(cur->path, path)) {
      cur->is_dir = cur->is_dir || is_dir;
      pthread_mutex_unlock(&temp_lock);
      if (real_free) real_free(copy);
      else free(copy);
      return;
    }
  }

  struct qdmsan_temp_path *entry =
      real_malloc ? real_malloc(sizeof(*entry)) : malloc(sizeof(*entry));
  if (entry) {
    entry->path = copy;
    entry->is_dir = is_dir;
    entry->next = temp_head;
    temp_head = entry;
    copy = NULL;
  }
  pthread_mutex_unlock(&temp_lock);

  if (copy) {
    if (real_free) real_free(copy);
    else free(copy);
  }
}

static int qdmsan_is_known_temp_path_locked(const char *path) {
  if (!path) return 0;
  for (struct qdmsan_temp_path *cur = temp_head; cur; cur = cur->next) {
    if (!strcmp(cur->path, path)) return 1;
    if (cur->is_dir && qdmsan_path_under_dir(path, cur->path)) return 1;
  }
  return 0;
}

static int qdmsan_is_known_temp_path(const char *path) {
  int ret;
  pthread_mutex_lock(&temp_lock);
  ret = qdmsan_is_known_temp_path_locked(path);
  pthread_mutex_unlock(&temp_lock);
  return ret;
}

static int qdmsan_is_under_known_temp_dir(const char *path) {
  int ret = 0;
  pthread_mutex_lock(&temp_lock);
  for (struct qdmsan_temp_path *cur = temp_head; cur; cur = cur->next) {
    if (cur->is_dir && qdmsan_path_under_dir(path, cur->path)) {
      ret = 1;
      break;
    }
  }
  pthread_mutex_unlock(&temp_lock);
  return ret;
}

static void qdmsan_forget_temp_path(const char *path) {
  if (!path) return;
  pthread_mutex_lock(&temp_lock);
  struct qdmsan_temp_path **prev = &temp_head;
  struct qdmsan_temp_path *cur = temp_head;
  while (cur) {
    if (!strcmp(cur->path, path)) {
      *prev = cur->next;
      pthread_mutex_unlock(&temp_lock);
      if (real_free) {
        real_free(cur->path);
        real_free(cur);
      } else {
        free(cur->path);
        free(cur);
      }
      return;
    }
    prev = &cur->next;
    cur = cur->next;
  }
  pthread_mutex_unlock(&temp_lock);
}

static int qdmsan_fd_in_range(int fd) {
  return fd >= 0 && fd < (int)(sizeof(temp_fds) / sizeof(temp_fds[0]));
}

static void qdmsan_set_temp_fd(int fd, int is_temp) {
  if (!qdmsan_fd_in_range(fd)) return;
  temp_fds[fd] = is_temp ? 1 : 0;
}

static int qdmsan_is_temp_fd(int fd) {
  return qdmsan_fd_in_range(fd) && temp_fds[fd];
}

static int qdmsan_open_needs_mode(int flags) {
  return (flags & O_CREAT) != 0;
}

static int qdmsan_fcntl_needs_arg(int cmd) {
  switch (cmd) {
    case F_DUPFD:
    case F_SETFD:
    case F_SETFL:
    case F_SETLK:
    case F_SETLKW:
    case F_GETLK:
#ifdef F_OFD_SETLK
    case F_OFD_SETLK:
#endif
#ifdef F_OFD_SETLKW
    case F_OFD_SETLKW:
#endif
#ifdef F_OFD_GETLK
    case F_OFD_GETLK:
#endif
#ifdef F_SETOWN
    case F_SETOWN:
#endif
#ifdef F_GETOWN_EX
    case F_GETOWN_EX:
#endif
#ifdef F_SETOWN_EX
    case F_SETOWN_EX:
#endif
#ifdef F_SETSIG
    case F_SETSIG:
#endif
#ifdef F_SETLEASE
    case F_SETLEASE:
#endif
#ifdef F_NOTIFY
    case F_NOTIFY:
#endif
#ifdef F_SETPIPE_SZ
    case F_SETPIPE_SZ:
#endif
#ifdef F_DUPFD_CLOEXEC
    case F_DUPFD_CLOEXEC:
#endif
      return 1;
    default:
      return 0;
  }
}

static int qdmsan_call_open(const char *path, int flags, mode_t mode,
                            int use64) {
  if (use64 && real_open64) {
    return qdmsan_open_needs_mode(flags) ? real_open64(path, flags, mode)
                                        : real_open64(path, flags);
  }
  if (real_open) {
    return qdmsan_open_needs_mode(flags) ? real_open(path, flags, mode)
                                        : real_open(path, flags);
  }
  return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}

static int qdmsan_call_openat(int dirfd, const char *path, int flags,
                              mode_t mode, int use64) {
  if (use64 && real_openat64) {
    return qdmsan_open_needs_mode(flags)
               ? real_openat64(dirfd, path, flags, mode)
               : real_openat64(dirfd, path, flags);
  }
  if (real_openat) {
    return qdmsan_open_needs_mode(flags) ? real_openat(dirfd, path, flags, mode)
                                        : real_openat(dirfd, path, flags);
  }
#ifdef SYS_openat
  return (int)syscall(SYS_openat, dirfd, path, flags, mode);
#else
  if (dirfd == AT_FDCWD) return qdmsan_call_open(path, flags, mode, use64);
  errno = ENOSYS;
  return -1;
#endif
}

static int qdmsan_openat_path_is_global(int dirfd, const char *path) {
  return dirfd == AT_FDCWD || (path && path[0] == '/');
}

static int qdmsan_mkstemp_template_ok(const char *tmpl, size_t len,
                                      int suffixlen, size_t *xoff) {
  if (!tmpl || suffixlen < 0) return 0;
  size_t suffix = (size_t)suffixlen;
  if (len < suffix || len - suffix < 6) return 0;
  size_t off = len - suffix - 6;
  for (size_t i = 0; i < 6; ++i) {
    if (tmpl[off + i] != 'X') return 0;
  }
  *xoff = off;
  return 1;
}

static void qdmsan_fill_mkstemp_suffix(char *suffix, unsigned call_num,
                                       unsigned attempt) {
  static const char alphabet[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  uint64_t x = qdmsan_mix64(qdmsan_fixed_rand_raw() ^
                            UINT64_C(0x6d6b7374656d7031) ^
                            ((uint64_t)call_num << 32) ^ attempt);
  for (size_t i = 0; i < 6; ++i) {
    suffix[i] = alphabet[x % (sizeof(alphabet) - 1)];
    x /= sizeof(alphabet) - 1;
    if (!x) x = qdmsan_mix64((uint64_t)call_num ^ attempt ^ i);
  }
}

static int qdmsan_deterministic_mkostemp(char *tmpl, size_t len, int suffixlen,
                                         int flags) {
  size_t xoff = 0;
  if (!qdmsan_mkstemp_template_ok(tmpl, len, suffixlen, &xoff)) {
    errno = EINVAL;
    return -1;
  }

  char *suffix = tmpl + xoff;
  char saved[6];
  memcpy(saved, suffix, sizeof(saved));
  unsigned call_num = __sync_fetch_and_add(&mkstemp_call_count, 1);
  int open_flags = flags | O_RDWR | O_CREAT | O_EXCL;

  for (unsigned attempt = 0; attempt < 128; ++attempt) {
    qdmsan_fill_mkstemp_suffix(suffix, call_num, attempt);
    int fd = qdmsan_call_open(tmpl, open_flags, 0600, 0);
    if (fd >= 0) {
      qdmsan_set_temp_fd(fd, 1);
      qdmsan_remember_temp_path(tmpl, 0);
      return fd;
    }
    if (errno != EEXIST) return -1;
  }

  memcpy(suffix, saved, sizeof(saved));
  errno = EEXIST;
  return -1;
}

static char *qdmsan_deterministic_mkdtemp(char *tmpl, size_t len) {
  size_t xoff = 0;
  if (!qdmsan_mkstemp_template_ok(tmpl, len, 0, &xoff)) {
    errno = EINVAL;
    return NULL;
  }

  char *suffix = tmpl + xoff;
  char saved[6];
  memcpy(saved, suffix, sizeof(saved));
  unsigned call_num = __sync_fetch_and_add(&mkstemp_call_count, 1);

  for (unsigned attempt = 0; attempt < 128; ++attempt) {
    qdmsan_fill_mkstemp_suffix(suffix, call_num, attempt);
    int ret = real_mkdir ? real_mkdir(tmpl, 0700) : mkdir(tmpl, 0700);
    if (!ret) {
      qdmsan_remember_temp_path(tmpl, 1);
      return tmpl;
    }
    if (errno != EEXIST) return NULL;
  }

  memcpy(suffix, saved, sizeof(saved));
  errno = EEXIST;
  return NULL;
}

static int qdmsan_temp_suppressed_call(int suppress) {
  if (suppress) qdmsan_suppress_enter();
  return suppress;
}

static void qdmsan_temp_suppressed_leave(int suppress) {
  if (suppress) qdmsan_suppress_leave();
}

static void qdmsan_normalize_stat(struct stat *st) {
  if (!st) return;
  st->st_atim.tv_sec = qdmsan_fixed_time_sec();
  st->st_atim.tv_nsec = (long)qdmsan_fixed_time_usec() * 1000L;
  st->st_mtim = st->st_atim;
  st->st_ctim = st->st_atim;
}

static void qdmsan_normalize_stat64(struct stat64 *st) {
  if (!st) return;
  st->st_atim.tv_sec = qdmsan_fixed_time_sec();
  st->st_atim.tv_nsec = (long)qdmsan_fixed_time_usec() * 1000L;
  st->st_mtim = st->st_atim;
  st->st_ctim = st->st_atim;
}

static void qdmsan_fill_fixed_rusage(struct rusage *usage) {
  if (!usage) return;
  memset(usage, 0, sizeof(*usage));
  suseconds_t usec = qdmsan_fixed_time_usec();
  usage->ru_utime.tv_sec = (time_t)(usec / 1000000);
  usage->ru_utime.tv_usec = usec % 1000000;
}

static size_t qdmsan_kernel_sigset_size(void) {
#ifdef _NSIG
  size_t kernel_size = _NSIG / 8;
  return kernel_size < sizeof(sigset_t) ? kernel_size : sizeof(sigset_t);
#else
  return sizeof(unsigned long) < sizeof(sigset_t) ? sizeof(unsigned long)
                                                  : sizeof(sigset_t);
#endif
}

static uint64_t qdmsan_hash_kernel_sigset(const sigset_t *set) {
  return qdmsan_hash_bytes(set, set ? qdmsan_kernel_sigset_size() : 0);
}

static void qdmsan_cleanup_temp_paths(void) {
  qdmsan_resolve();
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();

  pthread_mutex_lock(&temp_lock);
  struct qdmsan_temp_path *list = temp_head;
  temp_head = NULL;
  memset(temp_fds, 0, sizeof(temp_fds));
  pthread_mutex_unlock(&temp_lock);

  while (list) {
    struct qdmsan_temp_path *next = list->next;
    if (list->is_dir) {
      if (real_rmdir) real_rmdir(list->path);
      else rmdir(list->path);
    } else {
      if (real_unlink) real_unlink(list->path);
      else unlink(list->path);
    }
    if (real_free) {
      real_free(list->path);
      real_free(list);
    } else {
      free(list->path);
      free(list);
    }
    list = next;
  }

  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
}

static void qdmsan_record_raw_input(unsigned long pc, uint64_t value,
                                    unsigned long kind) {
  if (!qdmsan_result_mode()) qdmsan_record_libc(pc, (unsigned long)value, kind);
}

static uint64_t qdmsan_rotl64(uint64_t v, unsigned shift) {
  return (v << shift) | (v >> (64 - shift));
}

static uint64_t qdmsan_combine2(uint64_t a, uint64_t b) {
  return qdmsan_rotl64(a, 1) ^ b;
}

static void qdmsan_record_raw_input_pair(unsigned long pc, uint64_t a,
                                         uint64_t b, unsigned long kind) {
  qdmsan_record_raw_input(pc, qdmsan_combine2(a, b), kind);
}

static size_t qdmsan_in_addr_size(int af) {
  if (af == AF_INET) return 4;
  if (af == AF_INET6) return 16;
  return 0;
}

static uint64_t qdmsan_hash_tm_fields(const struct tm *tm) {
  if (!tm) return UINT64_C(0);
  uint64_t h = UINT64_C(1469598103934665603) ^ UINT64_C(0x746d);
  h ^= qdmsan_hash_bytes(&tm->tm_sec, sizeof(tm->tm_sec));
  h *= UINT64_C(1099511628211);
  h ^= qdmsan_hash_bytes(&tm->tm_min, sizeof(tm->tm_min));
  h *= UINT64_C(1099511628211);
  h ^= qdmsan_hash_bytes(&tm->tm_hour, sizeof(tm->tm_hour));
  h *= UINT64_C(1099511628211);
  h ^= qdmsan_hash_bytes(&tm->tm_mday, sizeof(tm->tm_mday));
  h *= UINT64_C(1099511628211);
  h ^= qdmsan_hash_bytes(&tm->tm_mon, sizeof(tm->tm_mon));
  h *= UINT64_C(1099511628211);
  h ^= qdmsan_hash_bytes(&tm->tm_year, sizeof(tm->tm_year));
  h *= UINT64_C(1099511628211);
  h ^= qdmsan_hash_bytes(&tm->tm_wday, sizeof(tm->tm_wday));
  h *= UINT64_C(1099511628211);
  h ^= qdmsan_hash_bytes(&tm->tm_yday, sizeof(tm->tm_yday));
  h *= UINT64_C(1099511628211);
  h ^= qdmsan_hash_bytes(&tm->tm_isdst, sizeof(tm->tm_isdst));
  h *= UINT64_C(1099511628211);
  return h;
}

static uint64_t qdmsan_hash_iov(const struct iovec *iov, int iovcnt) {
  uint64_t h = UINT64_C(1469598103934665603) ^ (uint64_t)(uint32_t)iovcnt;
  if (!iov || iovcnt <= 0) return h;
  if (!qdmsan_probably_user_pointer((uintptr_t)iov)) return h;
  int limit = iovcnt < 64 ? iovcnt : 64;
  for (int i = 0; i < limit; ++i) {
    h ^= qdmsan_hash_bytes(iov[i].iov_base, iov[i].iov_len);
    h *= UINT64_C(1099511628211);
  }
  return h;
}

static uint64_t qdmsan_hash_iov_prefix(const struct iovec *iov, int iovcnt,
                                       size_t consumed) {
  uint64_t h = UINT64_C(1469598103934665603) ^
               ((uint64_t)(uint32_t)iovcnt << 32) ^ (uint64_t)consumed;
  if (!iov || iovcnt <= 0 || !consumed) return h;
  if (!qdmsan_probably_user_pointer((uintptr_t)iov)) return h;
  int limit = iovcnt < 64 ? iovcnt : 64;
  for (int i = 0; i < limit && consumed; ++i) {
    size_t n = iov[i].iov_len < consumed ? iov[i].iov_len : consumed;
    h ^= qdmsan_hash_bytes(iov[i].iov_base, n);
    h *= UINT64_C(1099511628211);
    consumed -= n;
  }
  return h;
}

static uint64_t qdmsan_hash_argv(char *const argv[], int argc) {
  uint64_t h = UINT64_C(1469598103934665603) ^ (uint64_t)(uint32_t)argc;
  if (!argv) return h;

  int limit = argc > 0 ? argc : 64;
  if (limit > 64) limit = 64;
  for (int i = 0; i < limit; ++i) {
    if (!argv[i]) break;
    h ^= qdmsan_hash_cstr(argv[i], 256);
    h *= UINT64_C(1099511628211);
  }
  return h;
}

#define QDMSAN_SUPPRESS_COPY(ret_type, name, args, call_args) \
  ret_type name args { \
    qdmsan_resolve(); \
    if (in_qdmsan_hook) return real_##name call_args; \
    in_qdmsan_hook = 1; \
    qdmsan_suppress_enter(); \
    ret_type ret = real_##name call_args; \
    qdmsan_suppress_leave(); \
    in_qdmsan_hook = 0; \
    return ret; \
  }

#define QDMSAN_SUPPRESS_INT(name, args, call_args, fallback) \
  int name args { \
    qdmsan_resolve(); \
    if (in_qdmsan_hook) return real_##name ? real_##name call_args : fallback; \
    in_qdmsan_hook = 1; \
    qdmsan_suppress_enter(); \
    int ret = real_##name ? real_##name call_args : fallback; \
    qdmsan_suppress_leave(); \
    in_qdmsan_hook = 0; \
    return ret; \
  }

static void qdmsan_configure_quarantine(void) {
  const char *value = getenv("AFL_QDMSAN_QUARANTINE_MB");
  if (!value || !*value) value = getenv("QDMSAN_QUARANTINE_MB");
  if (!value || !*value) return;

  size_t mib = 0;
  for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
    if (*p < '0' || *p > '9') return;
    unsigned int digit = (unsigned int)(*p - '0');
    if (mib > (SIZE_MAX - digit) / 10) {
      quarantine_limit = SIZE_MAX;
      return;
    }
    mib = mib * 10 + digit;
  }
  if (mib > SIZE_MAX / (1024u * 1024u)) {
    quarantine_limit = SIZE_MAX;
  } else {
    quarantine_limit = mib * 1024u * 1024u;
  }
}

__attribute__((constructor)) static void qdmsan_init(void) {
  qdmsan_resolve();
  qdmsan_configure_quarantine();
  (void)qdmsan_result_mode();
  qdmsan_call(QDMSAN_ACTION_PREMAIN, 0, 0, 0);
  atexit(qdmsan_cleanup_temp_paths);
}

static int qdmsan_main_wrapper(int argc, char **argv, char **envp) {
  qdmsan_call(QDMSAN_ACTION_MAIN_STARTED, 0, 0, 0);
  return saved_main(argc, argv, envp);
}

int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv,
                      int (*init)(int, char **, char **), void (*fini)(void),
                      void (*rtld_fini)(void), void *stack_end) {
  qdmsan_resolve();
  saved_main = main;
  qdmsan_call(QDMSAN_ACTION_PREMAIN, 0, 0, 0);
  return real_libc_start_main(qdmsan_main_wrapper, argc, argv, init, fini,
                              rtld_fini, stack_end);
}

void *malloc(size_t size) {
  int entry_errno = errno;
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_malloc(size);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  void *ptr = qdmsan_allocate_managed(size, __alignof__(max_align_t), 0);
  int result_errno = ptr ? entry_errno : errno;
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  errno = result_errno;
  return ptr;
}

void *calloc(size_t nmemb, size_t size) {
  int entry_errno = errno;
  qdmsan_resolve();
  if (nmemb && size > SIZE_MAX / nmemb) {
    errno = ENOMEM;
    return NULL;
  }
  if (in_qdmsan_hook) return real_calloc(nmemb, size);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  void *ptr =
      qdmsan_allocate_managed(nmemb * size, __alignof__(max_align_t), 1);
  int result_errno = ptr ? entry_errno : errno;
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  errno = result_errno;
  return ptr;
}

void *realloc(void *ptr, size_t size) {
  int entry_errno = errno;
  qdmsan_resolve();
  int nested = in_qdmsan_hook;
  if (!ptr) {
    errno = entry_errno;
    return malloc(size);
  }

  /* A libc callback can realloc a managed pointer while an outer boundary
     wrapper holds the recursion guard.  Inspect ownership in both paths;
     managed user pointers are interior pointers, not libc allocations. */
  if (!nested) {
    in_qdmsan_hook = 1;
    qdmsan_suppress_enter();
  }
  size_t old_size = 0;
  int managed = qdmsan_managed_size(ptr, &old_size);
  void *new_ptr = NULL;
  int result_errno = entry_errno;

  if (!managed) {
    new_ptr = real_realloc(ptr, size);
    result_errno = (new_ptr || !size) ? entry_errno : errno;
  } else if (managed < 0) {
    errno = EINVAL;
    result_errno = errno;
  } else if (!size) {
    qdmsan_quarantine_managed(ptr);
  } else {
    new_ptr = qdmsan_allocate_managed(size, __alignof__(max_align_t), 0);
    if (new_ptr) {
      memcpy(new_ptr, ptr, old_size < size ? old_size : size);
      qdmsan_quarantine_managed(ptr);
    } else {
      result_errno = errno;
    }
  }
  if (!nested) {
    qdmsan_suppress_leave();
    in_qdmsan_hook = 0;
  }
  errno = result_errno;
  return new_ptr;
}

void *reallocarray(void *ptr, size_t nmemb, size_t size) {
  if (nmemb && size > SIZE_MAX / nmemb) {
    errno = ENOMEM;
    return NULL;
  }
  return realloc(ptr, nmemb * size);
}

void free(void *ptr) {
  int entry_errno = errno;
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    /* A real libc boundary called under the recursion guard may release an
       object that it allocated earlier through our public malloc hook.  Such
       an object is an interior user pointer once heap redzones are enabled,
       so forwarding it directly to libc free() corrupts the allocator. */
    if (ptr && !qdmsan_quarantine_managed(ptr)) real_free(ptr);
    return;
  }
  if (!ptr) {
    errno = entry_errno;
    return;
  }
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  if (!qdmsan_quarantine_managed(ptr)) real_free(ptr);
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  errno = entry_errno;
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
  int entry_errno = errno;
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_posix_memalign(memptr, alignment, size);
  if (!memptr || alignment < sizeof(void *) ||
      alignment % sizeof(void *) || !qdmsan_valid_alignment(alignment)) {
    errno = entry_errno;
    return EINVAL;
  }
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  void *ptr = qdmsan_allocate_managed(size, alignment, 0);
  int ret = ptr ? 0 : ENOMEM;
  if (ptr) *memptr = ptr;
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  errno = entry_errno;
  return ret;
}

void *memalign(size_t alignment, size_t size) {
  int entry_errno = errno;
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_memalign(alignment, size);
  if (!qdmsan_valid_alignment(alignment)) {
    errno = EINVAL;
    return NULL;
  }
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  void *ptr = qdmsan_allocate_managed(size, alignment, 0);
  int result_errno = ptr ? entry_errno : errno;
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  errno = result_errno;
  return ptr;
}

void *__libc_memalign(size_t alignment, size_t size) {
  int entry_errno = errno;
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    if (real_libc_memalign) return real_libc_memalign(alignment, size);
    return real_memalign ? real_memalign(alignment, size) : NULL;
  }

  if (!qdmsan_valid_alignment(alignment)) {
    errno = EINVAL;
    return NULL;
  }

  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  void *ptr = qdmsan_allocate_managed(size, alignment, 0);
  int result_errno = ptr ? entry_errno : errno;
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  errno = result_errno;
  return ptr;
}

void *aligned_alloc(size_t alignment, size_t size) {
  int entry_errno = errno;
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_aligned_alloc(alignment, size);
  if (!qdmsan_valid_alignment(alignment) || size % alignment) {
    errno = EINVAL;
    return NULL;
  }
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  void *ptr = qdmsan_allocate_managed(size, alignment, 0);
  int result_errno = ptr ? entry_errno : errno;
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  errno = result_errno;
  return ptr;
}

void *valloc(size_t size) {
  int entry_errno = errno;
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_valloc(size);
  long page = sysconf(_SC_PAGESIZE);
  size_t alignment = page > 0 ? (size_t)page : 4096u;
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  void *ptr = qdmsan_allocate_managed(size, alignment, 0);
  int result_errno = ptr ? entry_errno : errno;
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  errno = result_errno;
  return ptr;
}

void *pvalloc(size_t size) {
  int entry_errno = errno;
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_pvalloc(size);
  long page = sysconf(_SC_PAGESIZE);
  size_t alignment = page > 0 ? (size_t)page : 4096u;
  if (size > SIZE_MAX - (alignment - 1)) {
    errno = ENOMEM;
    return NULL;
  }
  size_t rounded = (size + alignment - 1) & ~(alignment - 1);
  if (!rounded) rounded = alignment;
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  void *ptr = qdmsan_allocate_managed(rounded, alignment, 0);
  int result_errno = ptr ? entry_errno : errno;
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  errno = result_errno;
  return ptr;
}

size_t malloc_usable_size(void *ptr) {
  int entry_errno = errno;
  qdmsan_resolve();
  if (!ptr) {
    errno = entry_errno;
    return 0;
  }

  size_t size = 0;
  int managed = qdmsan_managed_size(ptr, &size);
  if (managed) {
    errno = entry_errno;
    return managed > 0 ? size : 0;
  }
  size = real_malloc_usable_size ? real_malloc_usable_size(ptr) : 0;
  errno = entry_errno;
  return size;
}

QDMSAN_SUPPRESS_COPY(char *, strcpy, (char *dst, const char *src), (dst, src))
QDMSAN_SUPPRESS_COPY(char *, strncpy,
                     (char *dst, const char *src, size_t n), (dst, src, n))
QDMSAN_SUPPRESS_COPY(char *, stpcpy, (char *dst, const char *src), (dst, src))
QDMSAN_SUPPRESS_COPY(char *, stpncpy,
                     (char *dst, const char *src, size_t n), (dst, src, n))
QDMSAN_SUPPRESS_COPY(char *, strcat, (char *dst, const char *src), (dst, src))
QDMSAN_SUPPRESS_COPY(char *, strncat,
                     (char *dst, const char *src, size_t n), (dst, src, n))
QDMSAN_SUPPRESS_COPY(wchar_t *, wcscpy,
                     (wchar_t *dst, const wchar_t *src), (dst, src))
QDMSAN_SUPPRESS_COPY(wchar_t *, wcsncpy,
                     (wchar_t *dst, const wchar_t *src, size_t n),
                     (dst, src, n))

int mkstemp(char *template) {
  qdmsan_resolve();
  if (!template) return real_mkstemp ? real_mkstemp(template) : -1;
  if (in_qdmsan_hook) {
    return real_mkstemp ? real_mkstemp(template) : -1;
  }
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  int ret = qdmsan_deterministic_mkostemp(template, strlen(template), 0, 0);
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  return ret;
}

int mkstemps(char *template, int suffixlen) {
  qdmsan_resolve();
  if (!template) {
    return real_mkstemps ? real_mkstemps(template, suffixlen) : -1;
  }
  if (in_qdmsan_hook) {
    return real_mkstemps ? real_mkstemps(template, suffixlen) : -1;
  }
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  int ret =
      qdmsan_deterministic_mkostemp(template, strlen(template), suffixlen, 0);
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  return ret;
}

int mkostemp(char *template, int flags) {
  qdmsan_resolve();
  if (!template) return real_mkostemp ? real_mkostemp(template, flags) : -1;
  if (in_qdmsan_hook) {
    return real_mkostemp ? real_mkostemp(template, flags) : -1;
  }
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  int ret = qdmsan_deterministic_mkostemp(template, strlen(template), 0, flags);
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  return ret;
}

int mkostemps(char *template, int suffixlen, int flags) {
  qdmsan_resolve();
  if (!template) {
    return real_mkostemps ? real_mkostemps(template, suffixlen, flags) : -1;
  }
  if (in_qdmsan_hook) {
    return real_mkostemps ? real_mkostemps(template, suffixlen, flags) : -1;
  }
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  int ret =
      qdmsan_deterministic_mkostemp(template, strlen(template), suffixlen, flags);
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  return ret;
}

int mkstemp64(char *template) {
  return mkstemp(template);
}

int mkstemps64(char *template, int suffixlen) {
  return mkstemps(template, suffixlen);
}

int mkostemp64(char *template, int flags) {
  return mkostemp(template, flags);
}

int mkostemps64(char *template, int suffixlen, int flags) {
  return mkostemps(template, suffixlen, flags);
}

char *mkdtemp(char *template) {
  qdmsan_resolve();
  if (!template) return real_mkdtemp ? real_mkdtemp(template) : NULL;
  if (in_qdmsan_hook) {
    return real_mkdtemp ? real_mkdtemp(template) : NULL;
  }
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  char *ret = qdmsan_deterministic_mkdtemp(template, strlen(template));
  qdmsan_suppress_leave();
  in_qdmsan_hook = 0;
  return ret;
}

int open(const char *path, int flags, ...) {
  mode_t mode = 0;
  if (qdmsan_open_needs_mode(flags)) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return qdmsan_call_open(path, flags, mode, 0);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int fd = qdmsan_call_open(path, flags, mode, 0);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (fd >= 0) {
    int is_temp = qdmsan_is_known_temp_path(path);
    qdmsan_set_temp_fd(fd, is_temp);
    if ((flags & O_CREAT) && qdmsan_is_under_known_temp_dir(path)) {
      qdmsan_remember_temp_path(path, 0);
      qdmsan_set_temp_fd(fd, 1);
    }
  }
  return fd;
}

int open64(const char *path, int flags, ...) {
  mode_t mode = 0;
  if (qdmsan_open_needs_mode(flags)) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return qdmsan_call_open(path, flags, mode, 1);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int fd = qdmsan_call_open(path, flags, mode, 1);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (fd >= 0) {
    int is_temp = qdmsan_is_known_temp_path(path);
    qdmsan_set_temp_fd(fd, is_temp);
    if ((flags & O_CREAT) && qdmsan_is_under_known_temp_dir(path)) {
      qdmsan_remember_temp_path(path, 0);
      qdmsan_set_temp_fd(fd, 1);
    }
  }
  return fd;
}

int openat(int dirfd, const char *path, int flags, ...) {
  mode_t mode = 0;
  if (qdmsan_open_needs_mode(flags)) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }
  qdmsan_resolve();
  int global_path = qdmsan_openat_path_is_global(dirfd, path);
  int suppress = global_path && qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return qdmsan_call_openat(dirfd, path, flags, mode, 0);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int fd = qdmsan_call_openat(dirfd, path, flags, mode, 0);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (fd >= 0) {
    int is_temp = global_path && qdmsan_is_known_temp_path(path);
    qdmsan_set_temp_fd(fd, is_temp);
    if (global_path && (flags & O_CREAT) &&
        qdmsan_is_under_known_temp_dir(path)) {
      qdmsan_remember_temp_path(path, 0);
      qdmsan_set_temp_fd(fd, 1);
    }
  }
  return fd;
}

int openat64(int dirfd, const char *path, int flags, ...) {
  mode_t mode = 0;
  if (qdmsan_open_needs_mode(flags)) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }
  qdmsan_resolve();
  int global_path = qdmsan_openat_path_is_global(dirfd, path);
  int suppress = global_path && qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return qdmsan_call_openat(dirfd, path, flags, mode, 1);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int fd = qdmsan_call_openat(dirfd, path, flags, mode, 1);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (fd >= 0) {
    int is_temp = global_path && qdmsan_is_known_temp_path(path);
    qdmsan_set_temp_fd(fd, is_temp);
    if (global_path && (flags & O_CREAT) &&
        qdmsan_is_under_known_temp_dir(path)) {
      qdmsan_remember_temp_path(path, 0);
      qdmsan_set_temp_fd(fd, 1);
    }
  }
  return fd;
}

int __open_2(const char *path, int flags) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return real___open_2 ? real___open_2(path, flags)
                         : qdmsan_call_open(path, flags, 0, 0);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int fd = real___open_2 ? real___open_2(path, flags)
                         : qdmsan_call_open(path, flags, 0, 0);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (fd >= 0) {
    int is_temp = qdmsan_is_known_temp_path(path);
    qdmsan_set_temp_fd(fd, is_temp);
    if ((flags & O_CREAT) && qdmsan_is_under_known_temp_dir(path)) {
      qdmsan_remember_temp_path(path, 0);
      qdmsan_set_temp_fd(fd, 1);
    }
  }
  return fd;
}

int __open64_2(const char *path, int flags) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return real___open64_2 ? real___open64_2(path, flags)
                           : qdmsan_call_open(path, flags, 0, 1);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int fd = real___open64_2 ? real___open64_2(path, flags)
                           : qdmsan_call_open(path, flags, 0, 1);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (fd >= 0) {
    int is_temp = qdmsan_is_known_temp_path(path);
    qdmsan_set_temp_fd(fd, is_temp);
    if ((flags & O_CREAT) && qdmsan_is_under_known_temp_dir(path)) {
      qdmsan_remember_temp_path(path, 0);
      qdmsan_set_temp_fd(fd, 1);
    }
  }
  return fd;
}

int __openat_2(int dirfd, const char *path, int flags) {
  qdmsan_resolve();
  int global_path = qdmsan_openat_path_is_global(dirfd, path);
  int suppress = global_path && qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return real___openat_2 ? real___openat_2(dirfd, path, flags)
                           : qdmsan_call_openat(dirfd, path, flags, 0, 0);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int fd = real___openat_2 ? real___openat_2(dirfd, path, flags)
                           : qdmsan_call_openat(dirfd, path, flags, 0, 0);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (fd >= 0) {
    int is_temp = global_path && qdmsan_is_known_temp_path(path);
    qdmsan_set_temp_fd(fd, is_temp);
    if (global_path && (flags & O_CREAT) &&
        qdmsan_is_under_known_temp_dir(path)) {
      qdmsan_remember_temp_path(path, 0);
      qdmsan_set_temp_fd(fd, 1);
    }
  }
  return fd;
}

int __openat64_2(int dirfd, const char *path, int flags) {
  qdmsan_resolve();
  int global_path = qdmsan_openat_path_is_global(dirfd, path);
  int suppress = global_path && qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return real___openat64_2 ? real___openat64_2(dirfd, path, flags)
                             : qdmsan_call_openat(dirfd, path, flags, 0, 1);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int fd = real___openat64_2 ? real___openat64_2(dirfd, path, flags)
                             : qdmsan_call_openat(dirfd, path, flags, 0, 1);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (fd >= 0) {
    int is_temp = global_path && qdmsan_is_known_temp_path(path);
    qdmsan_set_temp_fd(fd, is_temp);
    if (global_path && (flags & O_CREAT) &&
        qdmsan_is_under_known_temp_dir(path)) {
      qdmsan_remember_temp_path(path, 0);
      qdmsan_set_temp_fd(fd, 1);
    }
  }
  return fd;
}

int close(int fd) {
  qdmsan_resolve();
  int suppress = qdmsan_is_temp_fd(fd);
  int entered = !in_qdmsan_hook;
  if (entered) {
    in_qdmsan_hook = 1;
    qdmsan_temp_suppressed_call(suppress);
  }
  int ret = real_close ? real_close(fd) : (int)syscall(SYS_close, fd);
  if (entered) {
    qdmsan_temp_suppressed_leave(suppress);
    in_qdmsan_hook = 0;
  }
  if (!ret) qdmsan_set_temp_fd(fd, 0);
  return ret;
}

int dup(int oldfd) {
  qdmsan_resolve();
  int suppress = qdmsan_is_temp_fd(oldfd);
  int entered = !in_qdmsan_hook;
  if (entered) {
    in_qdmsan_hook = 1;
    qdmsan_temp_suppressed_call(suppress);
  }
  int ret = real_dup ? real_dup(oldfd) : (int)syscall(SYS_dup, oldfd);
  if (entered) {
    qdmsan_temp_suppressed_leave(suppress);
    in_qdmsan_hook = 0;
  }
  if (ret >= 0) qdmsan_set_temp_fd(ret, qdmsan_is_temp_fd(oldfd));
  return ret;
}

int dup2(int oldfd, int newfd) {
  qdmsan_resolve();
  int suppress = qdmsan_is_temp_fd(oldfd);
  int entered = !in_qdmsan_hook;
  if (entered) {
    in_qdmsan_hook = 1;
    qdmsan_temp_suppressed_call(suppress);
  }
  int ret = real_dup2 ? real_dup2(oldfd, newfd)
                      : (int)syscall(SYS_dup2, oldfd, newfd);
  if (entered) {
    qdmsan_temp_suppressed_leave(suppress);
    in_qdmsan_hook = 0;
  }
  if (ret >= 0) qdmsan_set_temp_fd(ret, qdmsan_is_temp_fd(oldfd));
  return ret;
}

int dup3(int oldfd, int newfd, int flags) {
  qdmsan_resolve();
  int suppress = qdmsan_is_temp_fd(oldfd);
  int entered = !in_qdmsan_hook;
  if (entered) {
    in_qdmsan_hook = 1;
    qdmsan_temp_suppressed_call(suppress);
  }
#ifdef SYS_dup3
  int ret = real_dup3 ? real_dup3(oldfd, newfd, flags)
                      : (int)syscall(SYS_dup3, oldfd, newfd, flags);
#else
  int ret = real_dup3 ? real_dup3(oldfd, newfd, flags) : -1;
  if (!real_dup3) errno = ENOSYS;
#endif
  if (entered) {
    qdmsan_temp_suppressed_leave(suppress);
    in_qdmsan_hook = 0;
  }
  if (ret >= 0) qdmsan_set_temp_fd(ret, qdmsan_is_temp_fd(oldfd));
  return ret;
}

int fcntl(int fd, int cmd, ...) {
  long arg = 0;
  int has_arg = qdmsan_fcntl_needs_arg(cmd);
  if (has_arg) {
    va_list ap;
    va_start(ap, cmd);
    arg = va_arg(ap, long);
    va_end(ap);
  }
  qdmsan_resolve();
  int suppress = qdmsan_is_temp_fd(fd);
  int entered = !in_qdmsan_hook;
  if (entered) {
    in_qdmsan_hook = 1;
    qdmsan_temp_suppressed_call(suppress);
  }
  int ret = real_fcntl ? (has_arg ? real_fcntl(fd, cmd, arg)
                                  : real_fcntl(fd, cmd))
                       : (int)syscall(SYS_fcntl, fd, cmd, arg);
  if (entered) {
    qdmsan_temp_suppressed_leave(suppress);
    in_qdmsan_hook = 0;
  }
  if (ret >= 0) {
    if (cmd == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
        || cmd == F_DUPFD_CLOEXEC
#endif
    ) {
      qdmsan_set_temp_fd(ret, qdmsan_is_temp_fd(fd));
    }
  }
  return ret;
}

FILE *fopen(const char *path, const char *mode) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) return real_fopen ? real_fopen(path, mode) : NULL;
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  FILE *ret = real_fopen ? real_fopen(path, mode) : NULL;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (ret && mode && (mode[0] == 'w' || mode[0] == 'a') &&
      qdmsan_is_under_known_temp_dir(path)) {
    qdmsan_remember_temp_path(path, 0);
  }
  if (ret && qdmsan_is_known_temp_path(path)) qdmsan_set_temp_fd(fileno(ret), 1);
  return ret;
}

FILE *fopen64(const char *path, const char *mode) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) return real_fopen64 ? real_fopen64(path, mode) : NULL;
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  FILE *ret = real_fopen64 ? real_fopen64(path, mode)
                           : (real_fopen ? real_fopen(path, mode) : NULL);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (ret && mode && (mode[0] == 'w' || mode[0] == 'a') &&
      qdmsan_is_under_known_temp_dir(path)) {
    qdmsan_remember_temp_path(path, 0);
  }
  if (ret && qdmsan_is_known_temp_path(path)) qdmsan_set_temp_fd(fileno(ret), 1);
  return ret;
}

FILE *freopen(const char *path, const char *mode, FILE *stream) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return real_freopen ? real_freopen(path, mode, stream) : NULL;
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  FILE *ret = real_freopen ? real_freopen(path, mode, stream) : NULL;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (ret && mode && (mode[0] == 'w' || mode[0] == 'a') &&
      qdmsan_is_under_known_temp_dir(path)) {
    qdmsan_remember_temp_path(path, 0);
  }
  if (ret && qdmsan_is_known_temp_path(path)) qdmsan_set_temp_fd(fileno(ret), 1);
  return ret;
}

FILE *freopen64(const char *path, const char *mode, FILE *stream) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return real_freopen64 ? real_freopen64(path, mode, stream) : NULL;
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  FILE *ret =
      real_freopen64 ? real_freopen64(path, mode, stream)
                     : (real_freopen ? real_freopen(path, mode, stream) : NULL);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (ret && mode && (mode[0] == 'w' || mode[0] == 'a') &&
      qdmsan_is_under_known_temp_dir(path)) {
    qdmsan_remember_temp_path(path, 0);
  }
  if (ret && qdmsan_is_known_temp_path(path)) qdmsan_set_temp_fd(fileno(ret), 1);
  return ret;
}

int fclose(FILE *stream) {
  qdmsan_resolve();
  int fd = stream ? fileno(stream) : -1;
  int suppress = qdmsan_is_temp_fd(fd);
  if (in_qdmsan_hook) return real_fclose ? real_fclose(stream) : EOF;
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real_fclose ? real_fclose(stream) : EOF;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret) qdmsan_set_temp_fd(fd, 0);
  return ret;
}

int mkdir(const char *path, mode_t mode) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) return real_mkdir ? real_mkdir(path, mode) : -1;
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real_mkdir ? real_mkdir(path, mode) : -1;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && qdmsan_is_under_known_temp_dir(path)) {
    qdmsan_remember_temp_path(path, 1);
  }
  return ret;
}

int unlink(const char *path) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) return real_unlink ? real_unlink(path) : -1;
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real_unlink ? real_unlink(path) : -1;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret) qdmsan_forget_temp_path(path);
  return ret;
}

int unlinkat(int dirfd, const char *path, int flags) {
  qdmsan_resolve();
  int suppress = dirfd == AT_FDCWD && qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return real_unlinkat ? real_unlinkat(dirfd, path, flags) : -1;
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real_unlinkat ? real_unlinkat(dirfd, path, flags) : -1;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && dirfd == AT_FDCWD) qdmsan_forget_temp_path(path);
  return ret;
}

int remove(const char *path) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) return real_remove ? real_remove(path) : -1;
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real_remove ? real_remove(path) : -1;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret) qdmsan_forget_temp_path(path);
  return ret;
}

int rmdir(const char *path) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) return real_rmdir ? real_rmdir(path) : -1;
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real_rmdir ? real_rmdir(path) : -1;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret) qdmsan_forget_temp_path(path);
  return ret;
}

int rename(const char *oldpath, const char *newpath) {
  qdmsan_resolve();
  int old_temp = qdmsan_is_known_temp_path(oldpath);
  int new_temp = qdmsan_is_known_temp_path(newpath);
  int suppress = old_temp || new_temp;
  if (in_qdmsan_hook) {
    return real_rename ? real_rename(oldpath, newpath) : -1;
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real_rename ? real_rename(oldpath, newpath) : -1;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret) {
    if (old_temp) qdmsan_forget_temp_path(oldpath);
    if (new_temp || qdmsan_is_under_known_temp_dir(newpath)) {
      qdmsan_remember_temp_path(newpath, 0);
    }
  }
  return ret;
}

int stat(const char *path, struct stat *buf) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) return real_stat ? real_stat(path, buf) : -1;
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real_stat ? real_stat(path, buf) : -1;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && suppress) qdmsan_normalize_stat(buf);
  return ret;
}

int lstat(const char *path, struct stat *buf) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) return real_lstat ? real_lstat(path, buf) : -1;
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real_lstat ? real_lstat(path, buf) : -1;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && suppress) qdmsan_normalize_stat(buf);
  return ret;
}

int fstat(int fd, struct stat *buf) {
  qdmsan_resolve();
  int suppress = qdmsan_is_temp_fd(fd);
  if (in_qdmsan_hook) return real_fstat ? real_fstat(fd, buf) : -1;
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real_fstat ? real_fstat(fd, buf) : -1;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && suppress) qdmsan_normalize_stat(buf);
  return ret;
}

int __xstat(int version, const char *path, struct stat *buf) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return real___xstat ? real___xstat(version, path, buf) : stat(path, buf);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real___xstat ? real___xstat(version, path, buf)
                         : (real_stat ? real_stat(path, buf) : -1);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && suppress) qdmsan_normalize_stat(buf);
  return ret;
}

int __lxstat(int version, const char *path, struct stat *buf) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return real___lxstat ? real___lxstat(version, path, buf) : lstat(path, buf);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real___lxstat ? real___lxstat(version, path, buf)
                          : (real_lstat ? real_lstat(path, buf) : -1);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && suppress) qdmsan_normalize_stat(buf);
  return ret;
}

int __fxstat(int version, int fd, struct stat *buf) {
  qdmsan_resolve();
  int suppress = qdmsan_is_temp_fd(fd);
  if (in_qdmsan_hook) {
    return real___fxstat ? real___fxstat(version, fd, buf) : fstat(fd, buf);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real___fxstat ? real___fxstat(version, fd, buf)
                          : (real_fstat ? real_fstat(fd, buf) : -1);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && suppress) qdmsan_normalize_stat(buf);
  return ret;
}

int stat64(const char *path, struct stat64 *buf) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) return real_stat64 ? real_stat64(path, buf) : -1;
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real_stat64 ? real_stat64(path, buf) : -1;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && suppress) qdmsan_normalize_stat64(buf);
  return ret;
}

int lstat64(const char *path, struct stat64 *buf) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) return real_lstat64 ? real_lstat64(path, buf) : -1;
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real_lstat64 ? real_lstat64(path, buf) : -1;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && suppress) qdmsan_normalize_stat64(buf);
  return ret;
}

int fstat64(int fd, struct stat64 *buf) {
  qdmsan_resolve();
  int suppress = qdmsan_is_temp_fd(fd);
  if (in_qdmsan_hook) return real_fstat64 ? real_fstat64(fd, buf) : -1;
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real_fstat64 ? real_fstat64(fd, buf) : -1;
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && suppress) qdmsan_normalize_stat64(buf);
  return ret;
}

int __xstat64(int version, const char *path, struct stat64 *buf) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return real___xstat64 ? real___xstat64(version, path, buf)
                          : stat64(path, buf);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real___xstat64 ? real___xstat64(version, path, buf)
                           : (real_stat64 ? real_stat64(path, buf) : -1);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && suppress) qdmsan_normalize_stat64(buf);
  return ret;
}

int __lxstat64(int version, const char *path, struct stat64 *buf) {
  qdmsan_resolve();
  int suppress = qdmsan_is_known_temp_path(path);
  if (in_qdmsan_hook) {
    return real___lxstat64 ? real___lxstat64(version, path, buf)
                           : lstat64(path, buf);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real___lxstat64 ? real___lxstat64(version, path, buf)
                            : (real_lstat64 ? real_lstat64(path, buf) : -1);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && suppress) qdmsan_normalize_stat64(buf);
  return ret;
}

int __fxstat64(int version, int fd, struct stat64 *buf) {
  qdmsan_resolve();
  int suppress = qdmsan_is_temp_fd(fd);
  if (in_qdmsan_hook) {
    return real___fxstat64 ? real___fxstat64(version, fd, buf)
                           : fstat64(fd, buf);
  }
  in_qdmsan_hook = 1;
  qdmsan_temp_suppressed_call(suppress);
  int ret = real___fxstat64 ? real___fxstat64(version, fd, buf)
                            : (real_fstat64 ? real_fstat64(fd, buf) : -1);
  qdmsan_temp_suppressed_leave(suppress);
  in_qdmsan_hook = 0;
  if (!ret && suppress) qdmsan_normalize_stat64(buf);
  return ret;
}

int memcmp(const void *s1, const void *s2, size_t n) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_memcmp ? real_memcmp(s1, s2, n) : 0;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  int ret = real_memcmp ? real_memcmp(s1, s2, n) : 0;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h1 = 0, h2 = 0;
  if (raw_mode) {
    size_t used = qdmsan_memcmp_used(s1, s2, n);
    h1 = qdmsan_hash_bytes(s1, used);
    h2 = qdmsan_hash_bytes(s2, used);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 1);
  if (raw_mode) {
    qdmsan_record_raw_input_pair(pc, h1, h2, 0x101);
  }
  in_qdmsan_hook = 0;
  return ret;
}

int bcmp(const void *s1, const void *s2, size_t n) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    if (real_bcmp) return real_bcmp(s1, s2, n);
    return real_memcmp ? real_memcmp(s1, s2, n) : 0;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  int ret = real_bcmp ? real_bcmp(s1, s2, n)
                      : (real_memcmp ? real_memcmp(s1, s2, n) : 0);
  int raw_mode = !qdmsan_result_mode();
  uint64_t h1 = 0, h2 = 0;
  if (raw_mode) {
    size_t used = qdmsan_memcmp_used(s1, s2, n);
    h1 = qdmsan_hash_bytes(s1, used);
    h2 = qdmsan_hash_bytes(s2, used);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 2);
  if (raw_mode) {
    qdmsan_record_raw_input_pair(pc, h1, h2, 0x102);
  }
  in_qdmsan_hook = 0;
  return ret;
}

int strcmp(const char *s1, const char *s2) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_strcmp ? real_strcmp(s1, s2) : 0;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  int ret = real_strcmp ? real_strcmp(s1, s2) : 0;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h1 = 0, h2 = 0;
  if (raw_mode) {
    size_t used = qdmsan_strcmp_used(s1, s2, 256, 0);
    h1 = qdmsan_hash_cstr(s1, used);
    h2 = qdmsan_hash_cstr(s2, used);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 3);
  if (raw_mode) {
    qdmsan_record_raw_input_pair(pc, h1, h2, 0x103);
  }
  in_qdmsan_hook = 0;
  return ret;
}

int strncmp(const char *s1, const char *s2, size_t n) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_strncmp ? real_strncmp(s1, s2, n) : 0;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  int ret = real_strncmp ? real_strncmp(s1, s2, n) : 0;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h1 = 0, h2 = 0;
  if (raw_mode) {
    size_t used = qdmsan_strcmp_used(s1, s2, n, 0);
    h1 = qdmsan_hash_cstr(s1, used);
    h2 = qdmsan_hash_cstr(s2, used);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 4);
  if (raw_mode) {
    qdmsan_record_raw_input_pair(pc, h1, h2, 0x104);
  }
  in_qdmsan_hook = 0;
  return ret;
}

int strcasecmp(const char *s1, const char *s2) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_strcasecmp ? real_strcasecmp(s1, s2) : 0;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  int ret = real_strcasecmp ? real_strcasecmp(s1, s2) : 0;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h1 = 0, h2 = 0;
  if (raw_mode) {
    size_t used = qdmsan_strcmp_used(s1, s2, 256, 1);
    h1 = qdmsan_hash_cstr(s1, used);
    h2 = qdmsan_hash_cstr(s2, used);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 5);
  if (raw_mode) {
    qdmsan_record_raw_input_pair(pc, h1, h2, 0x105);
  }
  in_qdmsan_hook = 0;
  return ret;
}

int strncasecmp(const char *s1, const char *s2, size_t n) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_strncasecmp ? real_strncasecmp(s1, s2, n) : 0;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  int ret = real_strncasecmp ? real_strncasecmp(s1, s2, n) : 0;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h1 = 0, h2 = 0;
  if (raw_mode) {
    size_t used = qdmsan_strcmp_used(s1, s2, n, 1);
    h1 = qdmsan_hash_cstr(s1, used);
    h2 = qdmsan_hash_cstr(s2, used);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 6);
  if (raw_mode) {
    qdmsan_record_raw_input_pair(pc, h1, h2, 0x106);
  }
  in_qdmsan_hook = 0;
  return ret;
}

size_t strlen(const char *s) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_strlen ? real_strlen(s) : 0;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  size_t ret = real_strlen ? real_strlen(s) : 0;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = raw_mode ? qdmsan_hash_cstr(s, ret + 1) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)ret, 0x10);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x110);
  in_qdmsan_hook = 0;
  return ret;
}

size_t strnlen(const char *s, size_t maxlen) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_strnlen ? real_strnlen(s, maxlen) : 0;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  size_t ret = real_strnlen ? real_strnlen(s, maxlen) : 0;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = 0;
  if (raw_mode) {
    size_t used = ret < maxlen ? ret + 1 : maxlen;
    h = qdmsan_hash_cstr(s, used);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)ret, 0x11);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x111);
  in_qdmsan_hook = 0;
  return ret;
}

size_t wcslen(const wchar_t *s) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_wcslen ? real_wcslen(s) : 0;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  size_t ret = real_wcslen ? real_wcslen(s) : 0;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = raw_mode ? qdmsan_hash_wcs(s, ret + 1) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)ret, 0x12);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x112);
  in_qdmsan_hook = 0;
  return ret;
}

size_t wcsnlen(const wchar_t *s, size_t maxlen) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_wcsnlen ? real_wcsnlen(s, maxlen) : 0;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  size_t ret = real_wcsnlen ? real_wcsnlen(s, maxlen) : 0;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = 0;
  if (raw_mode) {
    size_t used = ret < maxlen ? ret + 1 : maxlen;
    h = qdmsan_hash_wcs(s, used);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)ret, 0x13);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x113);
  in_qdmsan_hook = 0;
  return ret;
}

void *memchr(const void *s, int c, size_t n) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_memchr ? real_memchr(s, c, n) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  void *ret = real_memchr ? real_memchr(s, c, n) : NULL;
  uintptr_t off = ret ? (uintptr_t)((const char *)ret - (const char *)s)
                      : UINTPTR_MAX;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = 0;
  if (raw_mode) {
    size_t used = ret ? off + 1 : n;
    h = qdmsan_hash_bytes(s, used);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)off, 0x14);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x114);
  in_qdmsan_hook = 0;
  return ret;
}

void *memrchr(const void *s, int c, size_t n) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_memrchr ? real_memrchr(s, c, n) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  void *ret = real_memrchr ? real_memrchr(s, c, n) : NULL;
  uintptr_t off = ret ? (uintptr_t)((const char *)ret - (const char *)s)
                      : UINTPTR_MAX;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = 0;
  if (raw_mode) {
    size_t used = ret ? n - off : n;
    const char *scan = ret ? (const char *)s + off : (const char *)s;
    h = qdmsan_hash_bytes(scan, used);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)off, 0x15);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x115);
  in_qdmsan_hook = 0;
  return ret;
}

void *memmem(const void *haystack, size_t haystacklen, const void *needle,
             size_t needlelen) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_memmem ? real_memmem(haystack, haystacklen, needle, needlelen)
                       : NULL;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  void *ret = real_memmem ? real_memmem(haystack, haystacklen, needle, needlelen)
                          : NULL;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = raw_mode ? qdmsan_hash_bytes(haystack, haystacklen) : 0;
  uintptr_t off = ret ? (uintptr_t)((const char *)ret - (const char *)haystack)
                      : UINTPTR_MAX;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)off, 0x16);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x116);
  in_qdmsan_hook = 0;
  return ret;
}

char *strchr(const char *s, int c) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_strchr ? real_strchr(s, c) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  char *ret = real_strchr ? real_strchr(s, c) : NULL;
  uintptr_t off = ret ? (uintptr_t)(ret - s) : UINTPTR_MAX;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = 0;
  if (raw_mode) {
    size_t used = ret ? off + 1 : qdmsan_cstr_scan_used(s, 256);
    h = qdmsan_hash_cstr(s, used);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)off, 0x17);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x117);
  in_qdmsan_hook = 0;
  return ret;
}

char *strrchr(const char *s, int c) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_strrchr ? real_strrchr(s, c) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  char *ret = real_strrchr ? real_strrchr(s, c) : NULL;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = raw_mode ? qdmsan_hash_cstr(s, qdmsan_cstr_scan_used(s, 256)) : 0;
  uintptr_t off = ret ? (uintptr_t)(ret - s) : UINTPTR_MAX;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)off, 0x18);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x118);
  in_qdmsan_hook = 0;
  return ret;
}

char *strchrnul(const char *s, int c) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_strchrnul ? real_strchrnul(s, c) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  char *ret = real_strchrnul ? real_strchrnul(s, c) : NULL;
  uintptr_t off = ret ? (uintptr_t)(ret - s) : UINTPTR_MAX;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = 0;
  if (raw_mode) {
    size_t used = ret ? off + 1 : qdmsan_cstr_scan_used(s, 256);
    h = qdmsan_hash_cstr(s, used);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)off, 0x19);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x119);
  in_qdmsan_hook = 0;
  return ret;
}

char *strstr(const char *haystack, const char *needle) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_strstr ? real_strstr(haystack, needle) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  char *ret = real_strstr ? real_strstr(haystack, needle) : NULL;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = raw_mode ? qdmsan_hash_cstr(haystack, 256) : 0;
  uintptr_t off = ret ? (uintptr_t)(ret - haystack) : UINTPTR_MAX;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)off, 0x1a);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x11a);
  in_qdmsan_hook = 0;
  return ret;
}

char *strcasestr(const char *haystack, const char *needle) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_strcasestr ? real_strcasestr(haystack, needle) : NULL;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hh = qdmsan_hash_cstr(haystack, 256);
  uint64_t hn = qdmsan_hash_cstr(needle, 256);
  char *ret = real_strcasestr ? real_strcasestr(haystack, needle) : NULL;
  uintptr_t off = ret ? (uintptr_t)(ret - haystack) : UINTPTR_MAX;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)off, 0x60);
  qdmsan_record_raw_input(pc, hh, 0x160);
  qdmsan_record_raw_input(pc, hn, 0x260);
  in_qdmsan_hook = 0;
  return ret;
}

char *strtok(char *str, const char *delim) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_strtok ? real_strtok(str, delim) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hs = qdmsan_hash_cstr(str, 256);
  uint64_t hd = qdmsan_hash_cstr(delim, 256);
  char *ret = real_strtok ? real_strtok(str, delim) : NULL;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? 1ul : 0ul, 0x61);
  qdmsan_record_raw_input(pc, hs, 0x161);
  qdmsan_record_raw_input(pc, hd, 0x261);
  in_qdmsan_hook = 0;
  return ret;
}

char *strptime(const char *s, const char *format, struct tm *tm) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_strptime ? real_strptime(s, format, tm) : NULL;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hs = qdmsan_hash_cstr(s, 256);
  uint64_t hf = qdmsan_hash_cstr(format, 256);
  char *ret = real_strptime ? real_strptime(s, format, tm) : NULL;
  uintptr_t off = (ret && s) ? (uintptr_t)(ret - s) : UINTPTR_MAX;
  uint64_t ht = qdmsan_hash_tm_fields(tm);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)off, 0x62);
  qdmsan_record_libc(pc, ht, 0x362);
  qdmsan_record_raw_input(pc, hs, 0x162);
  qdmsan_record_raw_input(pc, hf, 0x262);
  in_qdmsan_hook = 0;
  return ret;
}

char *strpbrk(const char *s, const char *accept) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_strpbrk ? real_strpbrk(s, accept) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  char *ret = real_strpbrk ? real_strpbrk(s, accept) : NULL;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = raw_mode ? qdmsan_hash_cstr(s, 256) : 0;
  uintptr_t off = ret ? (uintptr_t)(ret - s) : UINTPTR_MAX;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)off, 0x1b);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x11b);
  in_qdmsan_hook = 0;
  return ret;
}

size_t strspn(const char *s, const char *accept) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_strspn ? real_strspn(s, accept) : 0;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  size_t ret = real_strspn ? real_strspn(s, accept) : 0;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = raw_mode ? qdmsan_hash_cstr(s, ret + 1) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)ret, 0x1c);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x11c);
  in_qdmsan_hook = 0;
  return ret;
}

size_t strcspn(const char *s, const char *reject) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_strcspn ? real_strcspn(s, reject) : 0;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  size_t ret = real_strcspn ? real_strcspn(s, reject) : 0;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = raw_mode ? qdmsan_hash_cstr(s, ret + 1) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)ret, 0x1d);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x11d);
  in_qdmsan_hook = 0;
  return ret;
}

void *memccpy(void *dest, const void *src, int c, size_t n) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_memccpy ? real_memccpy(dest, src, c, n) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  void *ret = real_memccpy ? real_memccpy(dest, src, c, n) : NULL;
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = 0;
  if (raw_mode) {
    size_t used = ret ? (size_t)((const char *)ret - (const char *)dest) : n;
    h = qdmsan_hash_bytes(src, used);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? 1ul : 0ul, 0x1e);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x11e);
  in_qdmsan_hook = 0;
  return ret;
}

/* strdup is a propagation boundary, not a UUM sink.  Optimized libc string
   scans may legally read within malloc's mapped padding beyond the requested
   source size; keep those implementation reads out of the heap-redzone plane.
   Unlike the general in_qdmsan_hook recursion guard, this dedicated guard does
   not bypass our malloc hook, so the returned object still receives QDMSAN
   redzones and remains eligible for later OOB/UAF detection. */
char *strdup(const char *s) {
  qdmsan_resolve();
  if (in_qdmsan_hook || in_qdmsan_transfer_hook) {
    return real_strdup ? real_strdup(s) : NULL;
  }

  in_qdmsan_transfer_hook = 1;
  qdmsan_suppress_enter();
  char *ret = real_strdup ? real_strdup(s) : NULL;
  qdmsan_suppress_leave();
  in_qdmsan_transfer_hook = 0;
  return ret;
}

char *__strdup(const char *s) {
  qdmsan_resolve();
  if (in_qdmsan_hook || in_qdmsan_transfer_hook) {
    if (real___strdup) return real___strdup(s);
    return real_strdup ? real_strdup(s) : NULL;
  }

  in_qdmsan_transfer_hook = 1;
  qdmsan_suppress_enter();
  char *ret = real___strdup ? real___strdup(s)
                            : (real_strdup ? real_strdup(s) : NULL);
  qdmsan_suppress_leave();
  in_qdmsan_transfer_hook = 0;
  return ret;
}

char *strndup(const char *s, size_t n) {
  qdmsan_resolve();
  if (in_qdmsan_hook || in_qdmsan_transfer_hook) {
    return real_strndup ? real_strndup(s, n) : NULL;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_transfer_hook = 1;
  qdmsan_suppress_enter();
  char *ret = real_strndup ? real_strndup(s, n) : NULL;
  size_t used = qdmsan_cstr_scan_used(s, n);
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = raw_mode ? qdmsan_hash_cstr(s, used) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, qdmsan_cstr_observed_len(s, used), 0x1f);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x11f);
  in_qdmsan_transfer_hook = 0;
  return ret;
}

char *__strndup(const char *s, size_t n) {
  qdmsan_resolve();
  if (in_qdmsan_hook || in_qdmsan_transfer_hook) {
    if (real___strndup) return real___strndup(s, n);
    return real_strndup ? real_strndup(s, n) : NULL;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_transfer_hook = 1;
  qdmsan_suppress_enter();
  char *ret = real___strndup ? real___strndup(s, n)
                             : (real_strndup ? real_strndup(s, n) : NULL);
  size_t used = qdmsan_cstr_scan_used(s, n);
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = raw_mode ? qdmsan_hash_cstr(s, used) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, qdmsan_cstr_observed_len(s, used), 0x22);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x122);
  in_qdmsan_transfer_hook = 0;
  return ret;
}

wchar_t *wcsdup(const wchar_t *s) {
  qdmsan_resolve();
  if (in_qdmsan_hook || in_qdmsan_transfer_hook) {
    return real_wcsdup ? real_wcsdup(s) : NULL;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_transfer_hook = 1;
  qdmsan_suppress_enter();
  wchar_t *ret = real_wcsdup ? real_wcsdup(s) : NULL;
  size_t used = qdmsan_wcs_scan_used(s, 64);
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = raw_mode ? qdmsan_hash_wcs(s, used) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, qdmsan_wcs_observed_len(s, used), 0x20);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x120);
  in_qdmsan_transfer_hook = 0;
  return ret;
}

wchar_t *wcscat(wchar_t *dest, const wchar_t *src) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_wcscat ? real_wcscat(dest, src) : dest;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  size_t dest_used = qdmsan_wcs_scan_used(dest, 64);
  size_t src_used = qdmsan_wcs_scan_used(src, 64);
  uint64_t hd = qdmsan_hash_wcs(dest, dest_used);
  uint64_t hs = qdmsan_hash_wcs(src, src_used);
  wchar_t *ret = real_wcscat ? real_wcscat(dest, src) : dest;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, qdmsan_wcs_observed_len(src, src_used), 0x63);
  qdmsan_record_raw_input(pc, hd, 0x163);
  qdmsan_record_raw_input(pc, hs, 0x263);
  in_qdmsan_hook = 0;
  return ret;
}

wchar_t *wcsncat(wchar_t *dest, const wchar_t *src, size_t n) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_wcsncat ? real_wcsncat(dest, src, n) : dest;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  wchar_t *ret = real_wcsncat ? real_wcsncat(dest, src, n) : dest;
  size_t used = qdmsan_wcs_scan_used(src, n);
  int raw_mode = !qdmsan_result_mode();
  uint64_t h = raw_mode ? qdmsan_hash_wcs(src, used) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, qdmsan_wcs_observed_len(src, used), 0x21);
  if (raw_mode) qdmsan_record_libc(pc, h, 0x121);
  in_qdmsan_hook = 0;
  return ret;
}

ssize_t write(int fd, const void *buf, size_t count) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_write ? real_write(fd, buf, count)
                      : syscall(SYS_write, fd, buf, count);
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  ssize_t ret = real_write ? real_write(fd, buf, count)
                           : syscall(SYS_write, fd, buf, count);
  uint64_t h = ret > 0 ? qdmsan_hash_bytes(buf, (size_t)ret) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x130);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x30);
  in_qdmsan_hook = 0;
  return ret;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_pwrite ? real_pwrite(fd, buf, count, offset) : -1;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  ssize_t ret = real_pwrite ? real_pwrite(fd, buf, count, offset) : -1;
  uint64_t h = ret > 0 ? qdmsan_hash_bytes(buf, (size_t)ret) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x131);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x31);
  in_qdmsan_hook = 0;
  return ret;
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off64_t offset) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_pwrite64 ? real_pwrite64(fd, buf, count, offset) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  ssize_t ret = real_pwrite64 ? real_pwrite64(fd, buf, count, offset) : -1;
  uint64_t h = ret > 0 ? qdmsan_hash_bytes(buf, (size_t)ret) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x132);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x32);
  in_qdmsan_hook = 0;
  return ret;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_writev ? real_writev(fd, iov, iovcnt) : -1;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  ssize_t ret = real_writev ? real_writev(fd, iov, iovcnt) : -1;
  uint64_t h = ret > 0 ? qdmsan_hash_iov_prefix(iov, iovcnt, (size_t)ret) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x133);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x33);
  in_qdmsan_hook = 0;
  return ret;
}

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_pwritev ? real_pwritev(fd, iov, iovcnt, offset) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  ssize_t ret = real_pwritev ? real_pwritev(fd, iov, iovcnt, offset) : -1;
  uint64_t h = ret > 0 ? qdmsan_hash_iov_prefix(iov, iovcnt, (size_t)ret) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x134);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x34);
  in_qdmsan_hook = 0;
  return ret;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_send ? real_send(sockfd, buf, len, flags) : -1;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  ssize_t ret = real_send ? real_send(sockfd, buf, len, flags) : -1;
  uint64_t h = ret > 0 ? qdmsan_hash_bytes(buf, (size_t)ret) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x135);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x35);
  in_qdmsan_hook = 0;
  return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_sendto ? real_sendto(sockfd, buf, len, flags, dest_addr, addrlen)
                       : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  ssize_t ret = real_sendto ? real_sendto(sockfd, buf, len, flags, dest_addr,
                                          addrlen)
                            : -1;
  uint64_t h = ret > 0 ? qdmsan_hash_bytes(buf, (size_t)ret) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x136);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x36);
  in_qdmsan_hook = 0;
  return ret;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_sendmsg ? real_sendmsg(sockfd, msg, flags) : -1;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  ssize_t ret = real_sendmsg ? real_sendmsg(sockfd, msg, flags) : -1;
  uint64_t h = (ret > 0 && msg)
                   ? qdmsan_hash_iov_prefix(msg->msg_iov, msg->msg_iovlen,
                                            (size_t)ret)
                   : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x137);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x37);
  in_qdmsan_hook = 0;
  return ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_fwrite ? real_fwrite(ptr, size, nmemb, stream) : 0;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  size_t ret = real_fwrite ? real_fwrite(ptr, size, nmemb, stream) : 0;
  size_t consumed = size && ret <= (size_t)-1 / size ? ret * size : 0;
  uint64_t h = consumed ? qdmsan_hash_bytes(ptr, consumed) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x138);
  qdmsan_record_libc(pc, (unsigned long)ret, 0x38);
  in_qdmsan_hook = 0;
  return ret;
}

int fputs(const char *s, FILE *stream) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_fputs ? real_fputs(s, stream) : EOF;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(s, 256);
  int ret = real_fputs ? real_fputs(s, stream) : EOF;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x139);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x39);
  in_qdmsan_hook = 0;
  return ret;
}

int puts(const char *s) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_puts ? real_puts(s) : EOF;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(s, 256);
  int ret = real_puts ? real_puts(s) : EOF;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x13a);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x3a);
  in_qdmsan_hook = 0;
  return ret;
}

int rand(void) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_rand ? real_rand() : 0;
  }
  return (int)(qdmsan_fixed_rand_raw() & 0x7fffffffU);
}

void srand(unsigned int seed) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    if (real_srand) real_srand(seed);
  }
  (void)seed;
}

long random(void) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_random ? real_random() : 0;
  }
  return (long)(qdmsan_fixed_rand_raw() & 0x7fffffffU);
}

void srandom(unsigned int seed) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    if (real_srandom) real_srandom(seed);
  }
  (void)seed;
}

double drand48(void) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_drand48 ? real_drand48() : 0.0;
  }
  uint64_t x = qdmsan_fixed_rand_raw();
  return (double)(x & UINT64_C(0xffffffffffff)) / (double)(UINT64_C(1) << 48);
}

long lrand48(void) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_lrand48 ? real_lrand48() : 0;
  }
  return (long)(qdmsan_fixed_rand_raw() & 0x7fffffffU);
}

long mrand48(void) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_mrand48 ? real_mrand48() : 0;
  }
  return (long)((int32_t)(qdmsan_fixed_rand_raw() & UINT64_C(0xffffffff)));
}

void srand48(long seedval) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    if (real_srand48) real_srand48(seedval);
  }
  (void)seedval;
}

unsigned short *seed48(unsigned short seed16v[3]) {
  static unsigned short old_seed[3] = {0x33, 0x0e, 0xab};
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_seed48 ? real_seed48(seed16v) : old_seed;
  }
  (void)seed16v;
  return old_seed;
}

int random_r(struct random_data *buf, int32_t *result) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_random_r ? real_random_r(buf, result) : 0;
  }
  if (result) *result = (int32_t)(qdmsan_fixed_rand_raw() & 0x7fffffffU);
  (void)buf;
  return 0;
}

int srandom_r(unsigned int seed, struct random_data *buf) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_srandom_r ? real_srandom_r(seed, buf) : 0;
  }
  (void)seed;
  (void)buf;
  return 0;
}

int rand_r(unsigned int *seedp) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_rand_r ? real_rand_r(seedp) : 0;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  uint64_t h = qdmsan_hash_bytes(seedp, seedp ? sizeof(*seedp) : 0);
  int ret = (int)(qdmsan_fixed_rand_raw() & 0x7fffffffU);
  qdmsan_record_libc(pc, h, 0x140);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x40);
  return ret;
}

int drand48_r(struct drand48_data *buffer, double *result) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_drand48_r ? real_drand48_r(buffer, result) : 0;
  }
  if (result) {
    uint64_t x = qdmsan_fixed_rand_raw();
    *result =
        (double)(x & UINT64_C(0xffffffffffff)) / (double)(UINT64_C(1) << 48);
  }
  (void)buffer;
  return 0;
}

int lrand48_r(struct drand48_data *buffer, long *result) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_lrand48_r ? real_lrand48_r(buffer, result) : 0;
  }
  if (result) *result = (long)(qdmsan_fixed_rand_raw() & 0x7fffffffU);
  (void)buffer;
  return 0;
}

int mrand48_r(struct drand48_data *buffer, long *result) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_mrand48_r ? real_mrand48_r(buffer, result) : 0;
  }
  if (result) {
    *result =
        (long)((int32_t)(qdmsan_fixed_rand_raw() & UINT64_C(0xffffffff)));
  }
  (void)buffer;
  return 0;
}

int srand48_r(long seedval, struct drand48_data *buffer) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_srand48_r ? real_srand48_r(seedval, buffer) : 0;
  }
  (void)seedval;
  (void)buffer;
  return 0;
}

time_t time(time_t *tloc) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_time ? real_time(tloc) : (time_t)-1;
  }
  time_t ret = qdmsan_fixed_time_sec();
  if (tloc) *tloc = ret;
  return ret;
}

int gettimeofday(struct timeval *tv, void *tz) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_gettimeofday ? real_gettimeofday(tv, tz) : -1;
  }
  if (tv) {
    tv->tv_sec = qdmsan_fixed_time_sec();
    tv->tv_usec = qdmsan_fixed_time_usec();
  }
  if (tz) memset(tz, 0, 2 * sizeof(int));
  return 0;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_clock_gettime ? real_clock_gettime(clk_id, tp) : -1;
  }
  /* Validate the clock without consuming a real timestamp.  getres accepts
     NULL and also validates Linux dynamic clock IDs. */
  qdmsan_resolve();
  if (!real_clock_getres || real_clock_getres(clk_id, NULL) < 0) return -1;
  if (tp) {
    tp->tv_sec = qdmsan_fixed_time_sec();
    tp->tv_nsec = (long)qdmsan_fixed_time_usec() * 1000L;
  }
  return 0;
}

int clock_getres(clockid_t clk_id, struct timespec *res) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_clock_getres ? real_clock_getres(clk_id, res) : -1;
  }
  qdmsan_resolve();
  if (!real_clock_getres || real_clock_getres(clk_id, NULL) < 0) return -1;
  if (res) {
    res->tv_sec = 0;
    res->tv_nsec = 1;
  }
  return 0;
}

int ftime(struct timeb *tp) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_ftime ? real_ftime(tp) : -1;
  }
  if (tp) {
    tp->time = qdmsan_fixed_time_sec();
    tp->millitm = (unsigned short)(qdmsan_fixed_time_usec() / 1000);
    tp->timezone = 0;
    tp->dstflag = 0;
  }
  return 0;
}

clock_t times(struct tms *buf) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_times ? real_times(buf) : (clock_t)-1;
  }
  if (buf) memset(buf, 0, sizeof(*buf));
  return (clock_t)1000;
}

clock_t clock(void) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_clock ? real_clock() : (clock_t)-1;
  }
  unsigned long call_num = __sync_fetch_and_add(&clock_call_count, 1);
  return (clock_t)((unsigned long)qdmsan_fixed_time_usec() + call_num);
}

int getrusage(int who, struct rusage *usage) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_getrusage ? real_getrusage(who, usage) : -1;
  }
  int ret = real_getrusage ? real_getrusage(who, usage) : -1;
  if (!ret) qdmsan_fill_fixed_rusage(usage);
  return ret;
}

struct tm *localtime(const time_t *timep) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_localtime ? real_localtime(timep) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(timep, timep ? sizeof(*timep) : 0);
  struct tm *ret = real_localtime ? real_localtime(timep) : NULL;
  uint64_t ho = qdmsan_hash_tm_fields(ret);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? ho : 0, 0x64);
  qdmsan_record_raw_input(pc, hi, 0x164);
  in_qdmsan_hook = 0;
  return ret;
}

struct tm *localtime_r(const time_t *timep, struct tm *result) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_localtime_r ? real_localtime_r(timep, result) : NULL;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(timep, timep ? sizeof(*timep) : 0);
  struct tm *ret = real_localtime_r ? real_localtime_r(timep, result) : NULL;
  uint64_t ho = qdmsan_hash_tm_fields(ret);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? ho : 0, 0x65);
  qdmsan_record_raw_input(pc, hi, 0x165);
  in_qdmsan_hook = 0;
  return ret;
}

struct tm *gmtime(const time_t *timep) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_gmtime ? real_gmtime(timep) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(timep, timep ? sizeof(*timep) : 0);
  struct tm *ret = real_gmtime ? real_gmtime(timep) : NULL;
  uint64_t ho = qdmsan_hash_tm_fields(ret);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? ho : 0, 0x66);
  qdmsan_record_raw_input(pc, hi, 0x166);
  in_qdmsan_hook = 0;
  return ret;
}

struct tm *gmtime_r(const time_t *timep, struct tm *result) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_gmtime_r ? real_gmtime_r(timep, result) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(timep, timep ? sizeof(*timep) : 0);
  struct tm *ret = real_gmtime_r ? real_gmtime_r(timep, result) : NULL;
  uint64_t ho = qdmsan_hash_tm_fields(ret);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? ho : 0, 0x67);
  qdmsan_record_raw_input(pc, hi, 0x167);
  in_qdmsan_hook = 0;
  return ret;
}

char *ctime(const time_t *timep) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_ctime ? real_ctime(timep) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(timep, timep ? sizeof(*timep) : 0);
  char *ret = real_ctime ? real_ctime(timep) : NULL;
  uint64_t ho = qdmsan_hash_cstr(ret, 64);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? ho : 0, 0x68);
  qdmsan_record_raw_input(pc, hi, 0x168);
  in_qdmsan_hook = 0;
  return ret;
}

char *ctime_r(const time_t *timep, char *buf) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_ctime_r ? real_ctime_r(timep, buf) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(timep, timep ? sizeof(*timep) : 0);
  char *ret = real_ctime_r ? real_ctime_r(timep, buf) : NULL;
  uint64_t ho = qdmsan_hash_cstr(ret, 64);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? ho : 0, 0x69);
  qdmsan_record_raw_input(pc, hi, 0x169);
  in_qdmsan_hook = 0;
  return ret;
}

char *asctime(const struct tm *tm) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_asctime ? real_asctime(tm) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(tm, tm ? sizeof(*tm) : 0);
  char *ret = real_asctime ? real_asctime(tm) : NULL;
  uint64_t ho = qdmsan_hash_cstr(ret, 64);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? ho : 0, 0x6a);
  qdmsan_record_raw_input(pc, hi, 0x16a);
  in_qdmsan_hook = 0;
  return ret;
}

char *asctime_r(const struct tm *tm, char *buf) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_asctime_r ? real_asctime_r(tm, buf) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(tm, tm ? sizeof(*tm) : 0);
  char *ret = real_asctime_r ? real_asctime_r(tm, buf) : NULL;
  uint64_t ho = qdmsan_hash_cstr(ret, 64);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? ho : 0, 0x6b);
  qdmsan_record_raw_input(pc, hi, 0x16b);
  in_qdmsan_hook = 0;
  return ret;
}

time_t mktime(struct tm *tm) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_mktime ? real_mktime(tm) : (time_t)-1;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_tm_fields(tm);
  time_t ret = real_mktime ? real_mktime(tm) : (time_t)-1;
  uint64_t ho = qdmsan_hash_tm_fields(tm);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x6c);
  qdmsan_record_libc(pc, ho, 0x26c);
  qdmsan_record_raw_input(pc, hi, 0x16c);
  in_qdmsan_hook = 0;
  return ret;
}

int clock_settime(clockid_t clk_id, const struct timespec *tp) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_clock_settime ? real_clock_settime(clk_id, tp) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(tp, tp ? sizeof(*tp) : 0);
  int ret = real_clock_settime ? real_clock_settime(clk_id, tp) : -1;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x6d);
  qdmsan_record_raw_input(pc, hi, 0x16d);
  in_qdmsan_hook = 0;
  return ret;
}

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_getrandom ? real_getrandom(buf, buflen, flags) : -1;
  }
  /* Ask the host to validate flags with a zero-length request; no random
     bytes enter the deterministic sequence. */
  qdmsan_resolve();
  if (!real_getrandom || real_getrandom(NULL, 0, flags) < 0) return -1;
  if (!buf && buflen) {
    qdmsan_resolve();
    return real_getrandom ? real_getrandom(buf, buflen, flags) : -1;
  }
  return qdmsan_fixed_rand_bytes(buf, buflen) == 0 ? (ssize_t)buflen : -1;
}

int getentropy(void *buf, size_t buflen) {
  if (in_qdmsan_hook) {
    qdmsan_resolve();
    return real_getentropy ? real_getentropy(buf, buflen) : -1;
  }
  if (buflen > 256) {
    errno = EIO;
    return -1;
  }
  if (!buf && buflen) {
    qdmsan_resolve();
    return real_getentropy ? real_getentropy(buf, buflen) : -1;
  }
  return qdmsan_fixed_rand_bytes(buf, buflen);
}

unsigned int _ZNSt13random_device9_M_getvalEv(void *self) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_random_device_getval ? real_random_device_getval(self) : 0;
  }
  (void)self;
  return (unsigned int)(qdmsan_mix64(qdmsan_fixed_rand_raw()) & 0xffffffffU);
}

unsigned int _ZNSt13random_device16_M_getval_pretr1Ev(void *self) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_random_device_getval_pretr1
               ? real_random_device_getval_pretr1(self)
               : 0;
  }
  (void)self;
  return (unsigned int)(qdmsan_mix64(qdmsan_fixed_rand_raw()) & 0xffffffffU);
}

double _ZNKSt13random_device13_M_getentropyEv(const void *self) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_random_device_getentropy
               ? real_random_device_getentropy(self)
               : 0.0;
  }
  (void)self;
  return 32.0;
}

int setenv(const char *name, const char *value, int overwrite) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_setenv ? real_setenv(name, value, overwrite) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hn = qdmsan_hash_cstr(name, 256);
  uint64_t hv = qdmsan_hash_cstr(value, 256);
  int ret = real_setenv ? real_setenv(name, value, overwrite) : -1;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, hn, 0x141);
  qdmsan_record_libc(pc, hv, 0x241);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x41);
  in_qdmsan_hook = 0;
  return ret;
}

char *textdomain(const char *domainname) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_textdomain ? real_textdomain(domainname) : NULL;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(domainname, 256);
  char *ret = real_textdomain ? real_textdomain(domainname) : NULL;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x142);
  qdmsan_record_libc(pc, ret ? 1ul : 0ul, 0x42);
  in_qdmsan_hook = 0;
  return ret;
}

int pthread_setname_np(pthread_t thread, const char *name) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_pthread_setname_np ? real_pthread_setname_np(thread, name) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(name, 256);
  int ret = real_pthread_setname_np ? real_pthread_setname_np(thread, name) : -1;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x143);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x43);
  in_qdmsan_hook = 0;
  return ret;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_getaddrinfo ? real_getaddrinfo(node, service, hints, res)
                            : EAI_SYSTEM;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hn = qdmsan_hash_cstr(node, 256);
  uint64_t hs = qdmsan_hash_cstr(service, 256);
  uint64_t hh = qdmsan_hash_bytes(hints, hints ? sizeof(*hints) : 0);
  int ret = real_getaddrinfo ? real_getaddrinfo(node, service, hints, res)
                             : EAI_SYSTEM;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, hn, 0x144);
  qdmsan_record_libc(pc, hs, 0x244);
  qdmsan_record_libc(pc, hh, 0x344);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x44);
  in_qdmsan_hook = 0;
  return ret;
}

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_inet_ntop ? real_inet_ntop(af, src, dst, size) : NULL;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  size_t src_len = qdmsan_in_addr_size(af);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(src, src_len);
  const char *ret = real_inet_ntop ? real_inet_ntop(af, src, dst, size) : NULL;
  uint64_t ho = qdmsan_hash_cstr(ret, size);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? ho : 0, 0x6e);
  qdmsan_record_raw_input(pc, hi, 0x16e);
  in_qdmsan_hook = 0;
  return ret;
}

int inet_pton(int af, const char *src, void *dst) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_inet_pton ? real_inet_pton(af, src, dst) : -1;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  size_t dst_len = qdmsan_in_addr_size(af);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_cstr(src, 256);
  int ret = real_inet_pton ? real_inet_pton(af, src, dst) : -1;
  uint64_t ho = ret == 1 ? qdmsan_hash_bytes(dst, dst_len) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x6f);
  qdmsan_record_libc(pc, ho, 0x26f);
  qdmsan_record_raw_input(pc, hi, 0x16f);
  in_qdmsan_hook = 0;
  return ret;
}

int inet_aton(const char *cp, struct in_addr *inp) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_inet_aton ? real_inet_aton(cp, inp) : 0;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_cstr(cp, 256);
  int ret = real_inet_aton ? real_inet_aton(cp, inp) : 0;
  uint64_t ho = ret ? qdmsan_hash_bytes(inp, inp ? sizeof(*inp) : 0) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x70);
  qdmsan_record_libc(pc, ho, 0x270);
  qdmsan_record_raw_input(pc, hi, 0x170);
  in_qdmsan_hook = 0;
  return ret;
}

int __b64_ntop(unsigned char const *src, size_t srclength, char *target,
               size_t targsize) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real___b64_ntop ? real___b64_ntop(src, srclength, target, targsize)
                           : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(src, srclength);
  int ret = real___b64_ntop ? real___b64_ntop(src, srclength, target, targsize)
                            : -1;
  uint64_t ho = ret >= 0 ? qdmsan_hash_cstr(target, (size_t)ret + 1) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x71);
  qdmsan_record_libc(pc, ho, 0x271);
  qdmsan_record_raw_input(pc, hi, 0x171);
  in_qdmsan_hook = 0;
  return ret;
}

int __b64_pton(char const *src, unsigned char *target, size_t targsize) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real___b64_pton ? real___b64_pton(src, target, targsize) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_cstr(src, 256);
  int ret = real___b64_pton ? real___b64_pton(src, target, targsize) : -1;
  uint64_t ho = ret >= 0 ? qdmsan_hash_bytes(target, (size_t)ret) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x72);
  qdmsan_record_libc(pc, ho, 0x272);
  qdmsan_record_raw_input(pc, hi, 0x172);
  in_qdmsan_hook = 0;
  return ret;
}

int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen,
               struct passwd **result) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_getpwnam_r ? real_getpwnam_r(name, pwd, buf, buflen, result)
                           : ENOSYS;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(name, 256);
  int ret = real_getpwnam_r ? real_getpwnam_r(name, pwd, buf, buflen, result)
                            : ENOSYS;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x145);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x45);
  in_qdmsan_hook = 0;
  return ret;
}

struct passwd *getpwnam(const char *name) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_getpwnam ? real_getpwnam(name) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(name, 256);
  struct passwd *ret = real_getpwnam ? real_getpwnam(name) : NULL;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x154);
  qdmsan_record_libc(pc, ret ? 1ul : 0ul, 0x54);
  in_qdmsan_hook = 0;
  return ret;
}

struct group *getgrnam(const char *name) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_getgrnam ? real_getgrnam(name) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(name, 256);
  struct group *ret = real_getgrnam ? real_getgrnam(name) : NULL;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x155);
  qdmsan_record_libc(pc, ret ? 1ul : 0ul, 0x55);
  in_qdmsan_hook = 0;
  return ret;
}

int getgrnam_r(const char *name, struct group *grp, char *buf, size_t buflen,
               struct group **result) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_getgrnam_r ? real_getgrnam_r(name, grp, buf, buflen, result)
                           : ENOSYS;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(name, 256);
  int ret = real_getgrnam_r ? real_getgrnam_r(name, grp, buf, buflen, result)
                            : ENOSYS;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x156);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x56);
  in_qdmsan_hook = 0;
  return ret;
}

FILE *popen(const char *command, const char *type) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_popen ? real_popen(command, type) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hc = qdmsan_hash_cstr(command, 256);
  uint64_t ht = qdmsan_hash_cstr(type, 16);
  FILE *ret = real_popen ? real_popen(command, type) : NULL;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, hc, 0x146);
  qdmsan_record_libc(pc, ht, 0x246);
  qdmsan_record_libc(pc, ret ? 1ul : 0ul, 0x46);
  in_qdmsan_hook = 0;
  return ret;
}

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attrp, char *const argv[],
                char *const envp[]) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_posix_spawn ? real_posix_spawn(pid, path, file_actions, attrp,
                                               argv, envp)
                            : ENOSYS;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hp = qdmsan_hash_cstr(path, 256);
  uint64_t ha = qdmsan_hash_argv(argv, 0);
  int ret = real_posix_spawn ? real_posix_spawn(pid, path, file_actions, attrp,
                                                argv, envp)
                             : ENOSYS;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, hp, 0x147);
  qdmsan_record_libc(pc, ha, 0x247);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x47);
  in_qdmsan_hook = 0;
  return ret;
}

int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t *attrp, char *const argv[],
                 char *const envp[]) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_posix_spawnp ? real_posix_spawnp(pid, file, file_actions, attrp,
                                                 argv, envp)
                             : ENOSYS;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hf = qdmsan_hash_cstr(file, 256);
  uint64_t ha = qdmsan_hash_argv(argv, 0);
  int ret = real_posix_spawnp ? real_posix_spawnp(pid, file, file_actions,
                                                  attrp, argv, envp)
                              : ENOSYS;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, hf, 0x148);
  qdmsan_record_libc(pc, ha, 0x248);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x48);
  in_qdmsan_hook = 0;
  return ret;
}

size_t iconv(iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf,
             size_t *outbytesleft) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_iconv ? real_iconv(cd, inbuf, inbytesleft, outbuf, outbytesleft)
                      : (size_t)-1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  char *input = inbuf ? *inbuf : NULL;
  size_t input_left = inbytesleft ? *inbytesleft : 0;
  uint64_t h = qdmsan_hash_bytes(input, input_left);
  size_t ret = real_iconv ? real_iconv(cd, inbuf, inbytesleft, outbuf,
                                       outbytesleft)
                          : (size_t)-1;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x149);
  qdmsan_record_libc(pc, (unsigned long)ret, 0x49);
  in_qdmsan_hook = 0;
  return ret;
}

int regcomp(regex_t *preg, const char *pattern, int cflags) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_regcomp ? real_regcomp(preg, pattern, cflags) : REG_BADPAT;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hp = qdmsan_hash_cstr(pattern, 256);
  int ret = real_regcomp ? real_regcomp(preg, pattern, cflags) : REG_BADPAT;
  uint64_t ho = qdmsan_hash_bytes(preg, preg ? sizeof(*preg) : 0);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x75);
  qdmsan_record_libc(pc, ho, 0x275);
  qdmsan_record_raw_input(pc, hp, 0x175);
  in_qdmsan_hook = 0;
  return ret;
}

size_t regerror(int errcode, const regex_t *preg, char *errbuf,
                size_t errbuf_size) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_regerror ? real_regerror(errcode, preg, errbuf, errbuf_size) : 0;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_bytes(preg, preg ? sizeof(*preg) : 0);
  size_t ret = real_regerror ? real_regerror(errcode, preg, errbuf, errbuf_size)
                             : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x14a);
  qdmsan_record_libc(pc, (unsigned long)ret, 0x4a);
  in_qdmsan_hook = 0;
  return ret;
}

void regfree(regex_t *preg) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    if (real_regfree) real_regfree(preg);
    return;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_bytes(preg, preg ? sizeof(*preg) : 0);
  if (!qdmsan_compat_stubs_enabled() && real_regfree) real_regfree(preg);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x157);
  in_qdmsan_hook = 0;
}

size_t mbsrtowcs(wchar_t *dest, const char **src, size_t len, mbstate_t *ps) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_mbsrtowcs ? real_mbsrtowcs(dest, src, len, ps) : (size_t)-1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  const char *input = src ? *src : NULL;
  uint64_t hp = qdmsan_hash_bytes(src, src ? sizeof(*src) : 0);
  uint64_t hs = qdmsan_hash_bytes(ps, ps ? sizeof(*ps) : 0);
  size_t ret;
  if (qdmsan_compat_stubs_enabled() || !src ||
      !qdmsan_probably_user_pointer((uintptr_t)input)) {
    errno = EILSEQ;
    ret = (size_t)-1;
  } else {
    ret = real_mbsrtowcs ? real_mbsrtowcs(dest, src, len, ps)
                         : (errno = EILSEQ, (size_t)-1);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, hp, 0x158);
  qdmsan_record_libc(pc, hs, 0x258);
  qdmsan_record_libc(pc, (unsigned long)ret, 0x58);
  in_qdmsan_hook = 0;
  return ret;
}

size_t mbsnrtowcs(wchar_t *dest, const char **src, size_t nms, size_t len,
                  mbstate_t *ps) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_mbsnrtowcs ? real_mbsnrtowcs(dest, src, nms, len, ps)
                           : (size_t)-1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  const char *input = src ? *src : NULL;
  int input_ok = src && qdmsan_probably_user_pointer((uintptr_t)input);
  uint64_t hp = qdmsan_hash_bytes(src, src ? sizeof(*src) : 0);
  uint64_t hi = input_ok ? qdmsan_hash_bytes(input, nms) : 0;
  uint64_t hs = qdmsan_hash_bytes(ps, ps ? sizeof(*ps) : 0);
  size_t ret;
  if (qdmsan_compat_stubs_enabled() || !input_ok) {
    errno = EILSEQ;
    ret = (size_t)-1;
  } else {
    ret = real_mbsnrtowcs ? real_mbsnrtowcs(dest, src, nms, len, ps)
                          : (errno = EILSEQ, (size_t)-1);
  }
  uint64_t ho = (ret != (size_t)-1 && dest)
                    ? qdmsan_hash_bytes(dest, ret * sizeof(wchar_t))
                    : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)ret, 0x73);
  qdmsan_record_libc(pc, ho, 0x273);
  qdmsan_record_raw_input(pc, hp, 0x173);
  qdmsan_record_raw_input(pc, hi, 0x373);
  qdmsan_record_raw_input(pc, hs, 0x473);
  in_qdmsan_hook = 0;
  return ret;
}

size_t wcsrtombs(char *dest, const wchar_t **src, size_t len, mbstate_t *ps) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_wcsrtombs ? real_wcsrtombs(dest, src, len, ps) : (size_t)-1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  const wchar_t *input = src ? *src : NULL;
  uint64_t hp = qdmsan_hash_bytes(src, src ? sizeof(*src) : 0);
  uint64_t hs = qdmsan_hash_bytes(ps, ps ? sizeof(*ps) : 0);
  size_t ret;
  if (qdmsan_compat_stubs_enabled() || !src ||
      !qdmsan_probably_user_pointer((uintptr_t)input)) {
    errno = EILSEQ;
    ret = (size_t)-1;
  } else {
    ret = real_wcsrtombs ? real_wcsrtombs(dest, src, len, ps)
                         : (errno = EILSEQ, (size_t)-1);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, hp, 0x159);
  qdmsan_record_libc(pc, hs, 0x259);
  qdmsan_record_libc(pc, (unsigned long)ret, 0x59);
  in_qdmsan_hook = 0;
  return ret;
}

size_t wcsnrtombs(char *dest, const wchar_t **src, size_t nms, size_t len,
                  mbstate_t *ps) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_wcsnrtombs ? real_wcsnrtombs(dest, src, nms, len, ps)
                           : (size_t)-1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  size_t input_bytes =
      nms > (SIZE_MAX / sizeof(wchar_t)) ? SIZE_MAX : nms * sizeof(wchar_t);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  const wchar_t *input = src ? *src : NULL;
  int input_ok = src && qdmsan_probably_user_pointer((uintptr_t)input);
  uint64_t hp = qdmsan_hash_bytes(src, src ? sizeof(*src) : 0);
  uint64_t hi = input_ok ? qdmsan_hash_bytes(input, input_bytes) : 0;
  uint64_t hs = qdmsan_hash_bytes(ps, ps ? sizeof(*ps) : 0);
  size_t ret;
  if (qdmsan_compat_stubs_enabled() || !input_ok) {
    errno = EILSEQ;
    ret = (size_t)-1;
  } else {
    ret = real_wcsnrtombs ? real_wcsnrtombs(dest, src, nms, len, ps)
                          : (errno = EILSEQ, (size_t)-1);
  }
  uint64_t ho = (ret != (size_t)-1 && dest) ? qdmsan_hash_bytes(dest, ret) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)ret, 0x74);
  qdmsan_record_libc(pc, ho, 0x274);
  qdmsan_record_raw_input(pc, hp, 0x174);
  qdmsan_record_raw_input(pc, hi, 0x374);
  qdmsan_record_raw_input(pc, hs, 0x474);
  in_qdmsan_hook = 0;
  return ret;
}

size_t wcrtomb(char *s, wchar_t wc, mbstate_t *ps) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_wcrtomb ? real_wcrtomb(s, wc, ps) : (size_t)-1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_bytes(ps, ps ? sizeof(*ps) : 0);
  size_t ret;
  if (qdmsan_compat_stubs_enabled()) {
    errno = EILSEQ;
    ret = (size_t)-1;
  } else {
    ret = real_wcrtomb ? real_wcrtomb(s, wc, ps)
                       : (errno = EILSEQ, (size_t)-1);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x15a);
  qdmsan_record_libc(pc, (unsigned long)wc, 0x25a);
  qdmsan_record_libc(pc, (unsigned long)ret, 0x5a);
  in_qdmsan_hook = 0;
  return ret;
}

int capget(cap_user_header_t hdrp, cap_user_data_t datap) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_capget ? real_capget(hdrp, datap) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_bytes(hdrp, hdrp ? sizeof(*hdrp) : 0);
  int ret;
  if (qdmsan_compat_stubs_enabled()) {
    errno = EINVAL;
    ret = -1;
  } else {
    ret = real_capget ? real_capget(hdrp, datap) : (errno = ENOSYS, -1);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x15b);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x5b);
  in_qdmsan_hook = 0;
  return ret;
}

int xdr_bytes(void *xdrs, char **p, unsigned int *sizep,
              unsigned int maxsize) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_xdr_bytes ? real_xdr_bytes(xdrs, p, sizep, maxsize) : 0;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hp = qdmsan_hash_bytes(p, p ? sizeof(*p) : 0);
  uint64_t hs = qdmsan_hash_bytes(sizep, sizep ? sizeof(*sizep) : 0);
  int ret;
  if (qdmsan_compat_stubs_enabled()) {
    ret = 0;
  } else {
    ret = real_xdr_bytes ? real_xdr_bytes(xdrs, p, sizep, maxsize) : 0;
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, hp, 0x15c);
  qdmsan_record_libc(pc, hs, 0x25c);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x5c);
  in_qdmsan_hook = 0;
  return ret;
}

int xdr_string(void *xdrs, char **p, unsigned int maxsize) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_xdr_string ? real_xdr_string(xdrs, p, maxsize) : 0;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_bytes(p, p ? sizeof(*p) : 0);
  int ret;
  if (qdmsan_compat_stubs_enabled()) {
    ret = 0;
  } else {
    ret = real_xdr_string ? real_xdr_string(xdrs, p, maxsize) : 0;
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x15d);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x5d);
  in_qdmsan_hook = 0;
  return ret;
}

void xdrrec_create(void *xdrs, unsigned int sndsize, unsigned int rcvsize,
                   char *handle, int (*rd)(char *, char *, int),
                   int (*wr)(char *, char *, int)) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    if (real_xdrrec_create) {
      real_xdrrec_create(xdrs, sndsize, rcvsize, handle, rd, wr);
    }
    return;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_bytes(xdrs, xdrs ? sizeof(int) : 0);
  if (!qdmsan_compat_stubs_enabled() && real_xdrrec_create) {
    real_xdrrec_create(xdrs, sndsize, rcvsize, handle, rd, wr);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x15e);
  in_qdmsan_hook = 0;
}

struct utmpx *pututxline(const struct utmpx *ut) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_pututxline ? real_pututxline(ut) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_bytes(ut, ut ? sizeof(*ut) : 0);
  struct utmpx *ret = real_pututxline ? real_pututxline(ut) : NULL;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x14b);
  qdmsan_record_libc(pc, ret ? 1ul : 0ul, 0x4b);
  in_qdmsan_hook = 0;
  return ret;
}

error_t argp_parse(const struct argp *argp, int argc, char **argv,
                   unsigned flags, int *arg_index, void *input) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_argp_parse ? real_argp_parse(argp, argc, argv, flags, arg_index,
                                             input)
                           : EINVAL;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_argv(argv, argc);
  error_t ret = real_argp_parse ? real_argp_parse(argp, argc, argv, flags,
                                                  arg_index, input)
                                : EINVAL;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x14c);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x4c);
  in_qdmsan_hook = 0;
  return ret;
}

sem_t *sem_open(const char *name, int oflag, ...) {
  mode_t mode = 0;
  unsigned int value = 0;
  if (oflag & O_CREAT) {
    va_list ap;
    va_start(ap, oflag);
    mode = va_arg(ap, mode_t);
    value = va_arg(ap, unsigned int);
    va_end(ap);
  }

  qdmsan_resolve();
  if (in_qdmsan_hook) {
    if (!real_sem_open) return SEM_FAILED;
    return (oflag & O_CREAT) ? real_sem_open(name, oflag, mode, value)
                             : real_sem_open(name, oflag);
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(name, 256);
  sem_t *ret = real_sem_open
                   ? ((oflag & O_CREAT) ? real_sem_open(name, oflag, mode, value)
                                        : real_sem_open(name, oflag))
                   : SEM_FAILED;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x14d);
  qdmsan_record_libc(pc, ret == SEM_FAILED ? 0ul : 1ul, 0x4d);
  in_qdmsan_hook = 0;
  return ret;
}

int sem_timedwait(sem_t *sem, const struct timespec *abs_timeout) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_sem_timedwait ? real_sem_timedwait(sem, abs_timeout) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_bytes(abs_timeout,
                                 abs_timeout ? sizeof(*abs_timeout) : 0);
  int ret = real_sem_timedwait ? real_sem_timedwait(sem, abs_timeout)
                               : (errno = ENOSYS, -1);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x76);
  qdmsan_record_raw_input(pc, h, 0x176);
  in_qdmsan_hook = 0;
  return ret;
}

int sem_unlink(const char *name) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_sem_unlink ? real_sem_unlink(name) : -1;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(name, 256);
  int ret = real_sem_unlink ? real_sem_unlink(name) : (errno = ENOSYS, -1);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x77);
  qdmsan_record_raw_input(pc, h, 0x177);
  in_qdmsan_hook = 0;
  return ret;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_sigprocmask ? real_sigprocmask(how, set, oldset) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_kernel_sigset(set);
  int ret = real_sigprocmask ? real_sigprocmask(how, set, oldset) : -1;
  uint64_t ho = (!ret && oldset) ? qdmsan_hash_kernel_sigset(oldset) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x78);
  qdmsan_record_libc(pc, ho, 0x278);
  qdmsan_record_raw_input(pc, hi, 0x178);
  in_qdmsan_hook = 0;
  return ret;
}

int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_pthread_sigmask ? real_pthread_sigmask(how, set, oldset) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_kernel_sigset(set);
  int ret = real_pthread_sigmask ? real_pthread_sigmask(how, set, oldset) : -1;
  uint64_t ho = (!ret && oldset) ? qdmsan_hash_kernel_sigset(oldset) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x79);
  qdmsan_record_libc(pc, ho, 0x279);
  qdmsan_record_raw_input(pc, hi, 0x179);
  in_qdmsan_hook = 0;
  return ret;
}

int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_sigaction ? real_sigaction(signum, act, oldact) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = 0;
  if (act) {
    h = qdmsan_hash_bytes(&act->sa_flags, sizeof(act->sa_flags));
    if (act->sa_flags & SA_SIGINFO) {
      h = qdmsan_combine2(
          h, qdmsan_hash_bytes(&act->sa_sigaction, sizeof(act->sa_sigaction)));
    } else {
      h = qdmsan_combine2(
          h, qdmsan_hash_bytes(&act->sa_handler, sizeof(act->sa_handler)));
    }
    h = qdmsan_combine2(h, qdmsan_hash_kernel_sigset(&act->sa_mask));
  }
  int ret = real_sigaction ? real_sigaction(signum, act, oldact) : -1;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x7b);
  qdmsan_record_raw_input(pc, h, 0x17b);
  in_qdmsan_hook = 0;
  return ret;
}

int wordexp(const char *s, wordexp_t *p, int flags) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_wordexp ? real_wordexp(s, p, flags) : WRDE_BADCHAR;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(s, 256);
  int ret = real_wordexp ? real_wordexp(s, p, flags) : WRDE_BADCHAR;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x7a);
  qdmsan_record_raw_input(pc, h, 0x17a);
  in_qdmsan_hook = 0;
  return ret;
}

char **backtrace_symbols(void *const *buffer, int size) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_backtrace_symbols ? real_backtrace_symbols(buffer, size) : NULL;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  size_t bytes = size > 0 ? (size_t)size * sizeof(*buffer) : 0;
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_bytes(buffer, bytes);
  char **ret = real_backtrace_symbols ? real_backtrace_symbols(buffer, size) : NULL;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? 1ul : 0ul, 0x7b);
  qdmsan_record_raw_input(pc, h, 0x17b);
  in_qdmsan_hook = 0;
  return ret;
}

int initgroups(const char *user, gid_t group) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_initgroups ? real_initgroups(user, group) : -1;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(user, 256);
  int ret = real_initgroups ? real_initgroups(user, group) : (errno = ENOSYS, -1);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x7c);
  qdmsan_record_raw_input(pc, h, 0x17c);
  in_qdmsan_hook = 0;
  return ret;
}

char *ether_ntoa(const struct ether_addr *addr) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_ether_ntoa ? real_ether_ntoa(addr) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(addr, addr ? sizeof(*addr) : 0);
  char *ret = real_ether_ntoa ? real_ether_ntoa(addr) : NULL;
  uint64_t ho = qdmsan_hash_cstr(ret, 64);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? ho : 0, 0x7d);
  qdmsan_record_raw_input(pc, hi, 0x17d);
  in_qdmsan_hook = 0;
  return ret;
}

struct ether_addr *ether_aton(const char *asc) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_ether_aton ? real_ether_aton(asc) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_cstr(asc, 256);
  struct ether_addr *ret = real_ether_aton ? real_ether_aton(asc) : NULL;
  uint64_t ho = qdmsan_hash_bytes(ret, ret ? sizeof(*ret) : 0);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? ho : 0, 0x7e);
  qdmsan_record_raw_input(pc, hi, 0x17e);
  in_qdmsan_hook = 0;
  return ret;
}

int ether_ntohost(char *hostname, const struct ether_addr *addr) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_ether_ntohost ? real_ether_ntohost(hostname, addr) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(addr, addr ? sizeof(*addr) : 0);
  int ret = real_ether_ntohost ? real_ether_ntohost(hostname, addr) : -1;
  uint64_t ho = !ret ? qdmsan_hash_cstr(hostname, 256) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x7f);
  qdmsan_record_libc(pc, ho, 0x27f);
  qdmsan_record_raw_input(pc, hi, 0x17f);
  in_qdmsan_hook = 0;
  return ret;
}

int ether_hostton(const char *hostname, struct ether_addr *addr) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_ether_hostton ? real_ether_hostton(hostname, addr) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_cstr(hostname, 256);
  int ret = real_ether_hostton ? real_ether_hostton(hostname, addr) : -1;
  uint64_t ho = !ret ? qdmsan_hash_bytes(addr, addr ? sizeof(*addr) : 0) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x80);
  qdmsan_record_libc(pc, ho, 0x280);
  qdmsan_record_raw_input(pc, hi, 0x180);
  in_qdmsan_hook = 0;
  return ret;
}

int ether_line(const char *line, struct ether_addr *addr, char *hostname) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_ether_line ? real_ether_line(line, addr, hostname) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_cstr(line, 256);
  int ret = real_ether_line ? real_ether_line(line, addr, hostname) : -1;
  uint64_t ha = !ret ? qdmsan_hash_bytes(addr, addr ? sizeof(*addr) : 0) : 0;
  uint64_t hh = !ret ? qdmsan_hash_cstr(hostname, 256) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x81);
  qdmsan_record_libc(pc, ha, 0x281);
  qdmsan_record_libc(pc, hh, 0x381);
  qdmsan_record_raw_input(pc, hi, 0x181);
  in_qdmsan_hook = 0;
  return ret;
}

char *ether_ntoa_r(const struct ether_addr *addr, char *buf) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_ether_ntoa_r ? real_ether_ntoa_r(addr, buf) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_bytes(addr, addr ? sizeof(*addr) : 0);
  char *ret = real_ether_ntoa_r ? real_ether_ntoa_r(addr, buf) : NULL;
  uint64_t ho = qdmsan_hash_cstr(ret, 64);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? ho : 0, 0x82);
  qdmsan_record_raw_input(pc, hi, 0x182);
  in_qdmsan_hook = 0;
  return ret;
}

struct ether_addr *ether_aton_r(const char *asc, struct ether_addr *addr) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_ether_aton_r ? real_ether_aton_r(asc, addr) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hi = qdmsan_hash_cstr(asc, 256);
  struct ether_addr *ret = real_ether_aton_r ? real_ether_aton_r(asc, addr) : NULL;
  uint64_t ho = ret ? qdmsan_hash_bytes(ret, sizeof(*ret)) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? ho : 0, 0x83);
  qdmsan_record_raw_input(pc, hi, 0x183);
  in_qdmsan_hook = 0;
  return ret;
}

unsigned int if_nametoindex(const char *ifname) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_if_nametoindex ? real_if_nametoindex(ifname) : 0;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(ifname, 256);
  unsigned int ret = real_if_nametoindex ? real_if_nametoindex(ifname) : 0;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)ret, 0x84);
  qdmsan_record_raw_input(pc, h, 0x184);
  in_qdmsan_hook = 0;
  return ret;
}

FILE *fdopen(int fd, const char *mode) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_fdopen ? real_fdopen(fd, mode) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(mode, 64);
  FILE *ret = real_fdopen ? real_fdopen(fd, mode) : NULL;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? 1ul : 0ul, 0x85);
  qdmsan_record_raw_input(pc, h, 0x185);
  in_qdmsan_hook = 0;
  return ret;
}

int getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_getgrouplist ? real_getgrouplist(user, group, groups, ngroups)
                             : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hn = qdmsan_hash_cstr(user, 256);
  uint64_t hg = qdmsan_hash_bytes(ngroups, ngroups ? sizeof(*ngroups) : 0);
  int ret = real_getgrouplist ? real_getgrouplist(user, group, groups, ngroups)
                              : -1;
  uint64_t ho = qdmsan_hash_bytes(ngroups, ngroups ? sizeof(*ngroups) : 0);
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x86);
  qdmsan_record_libc(pc, ho, 0x286);
  qdmsan_record_raw_input(pc, hn, 0x186);
  qdmsan_record_raw_input(pc, hg, 0x386);
  in_qdmsan_hook = 0;
  return ret;
}

struct protoent *getprotobyname(const char *name) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_getprotobyname ? real_getprotobyname(name) : NULL;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(name, 256);
  struct protoent *ret = real_getprotobyname ? real_getprotobyname(name) : NULL;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? 1ul : 0ul, 0x87);
  qdmsan_record_raw_input(pc, h, 0x187);
  in_qdmsan_hook = 0;
  return ret;
}

int getprotobyname_r(const char *name, struct protoent *result_buf, char *buf,
                     size_t buflen, struct protoent **result) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_getprotobyname_r
               ? real_getprotobyname_r(name, result_buf, buf, buflen, result)
               : ENOSYS;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(name, 256);
  int ret = real_getprotobyname_r
                ? real_getprotobyname_r(name, result_buf, buf, buflen, result)
                : ENOSYS;
  unsigned long present = (result && *result) ? 1ul : 0ul;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x88);
  qdmsan_record_libc(pc, present, 0x288);
  qdmsan_record_raw_input(pc, h, 0x188);
  in_qdmsan_hook = 0;
  return ret;
}

struct netent *getnetbyname(const char *name) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_getnetbyname ? real_getnetbyname(name) : NULL;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_cstr(name, 256);
  struct netent *ret = real_getnetbyname ? real_getnetbyname(name) : NULL;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, ret ? 1ul : 0ul, 0x89);
  qdmsan_record_raw_input(pc, h, 0x189);
  in_qdmsan_hook = 0;
  return ret;
}

int sigandset(sigset_t *set, const sigset_t *left, const sigset_t *right) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_sigandset ? real_sigandset(set, left, right) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hl = qdmsan_hash_bytes(left, left ? sizeof(*left) : 0);
  uint64_t hr = qdmsan_hash_bytes(right, right ? sizeof(*right) : 0);
  int ret = real_sigandset ? real_sigandset(set, left, right) : -1;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, hl, 0x14e);
  qdmsan_record_libc(pc, hr, 0x24e);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x4e);
  in_qdmsan_hook = 0;
  return ret;
}

int sigorset(sigset_t *set, const sigset_t *left, const sigset_t *right) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_sigorset ? real_sigorset(set, left, right) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t hl = qdmsan_hash_bytes(left, left ? sizeof(*left) : 0);
  uint64_t hr = qdmsan_hash_bytes(right, right ? sizeof(*right) : 0);
  int ret = real_sigorset ? real_sigorset(set, left, right) : -1;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, hl, 0x14f);
  qdmsan_record_libc(pc, hr, 0x24f);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x4f);
  in_qdmsan_hook = 0;
  return ret;
}

int sigwait(const sigset_t *set, int *sig) {
  qdmsan_resolve();
  if (in_qdmsan_hook) return real_sigwait ? real_sigwait(set, sig) : ENOSYS;
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_bytes(set, set ? sizeof(*set) : 0);
  int ret;
  if (qdmsan_compat_stubs_enabled()) {
    if (sig) *sig = 0;
    ret = EINVAL;
  } else {
    ret = real_sigwait ? real_sigwait(set, sig) : ENOSYS;
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x150);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x50);
  in_qdmsan_hook = 0;
  return ret;
}

int sigwaitinfo(const sigset_t *set, siginfo_t *info) {
  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_sigwaitinfo ? real_sigwaitinfo(set, info) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_bytes(set, set ? sizeof(*set) : 0);
  int ret;
  if (qdmsan_compat_stubs_enabled()) {
    (void)info;
    errno = EAGAIN;
    ret = -1;
  } else {
    ret = real_sigwaitinfo ? real_sigwaitinfo(set, info) : (errno = ENOSYS, -1);
  }
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x151);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x51);
  in_qdmsan_hook = 0;
  return ret;
}

int prctl(int option, ...) {
  unsigned long arg2, arg3, arg4, arg5;
  va_list ap;
  va_start(ap, option);
  arg2 = va_arg(ap, unsigned long);
  arg3 = va_arg(ap, unsigned long);
  arg4 = va_arg(ap, unsigned long);
  arg5 = va_arg(ap, unsigned long);
  va_end(ap);

  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_prctl ? real_prctl(option, arg2, arg3, arg4, arg5) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = 0;
#ifdef PR_SET_VMA
  if (option == PR_SET_VMA) {
    h = qdmsan_hash_cstr((const char *)arg5, 256);
  }
#endif
  int ret = real_prctl ? real_prctl(option, arg2, arg3, arg4, arg5) : -1;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x152);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x52);
  in_qdmsan_hook = 0;
  return ret;
}

long ptrace(enum __ptrace_request request, ...) {
  pid_t pid;
  void *addr;
  void *data;
  va_list ap;
  va_start(ap, request);
  pid = va_arg(ap, pid_t);
  addr = va_arg(ap, void *);
  data = va_arg(ap, void *);
  va_end(ap);

  qdmsan_resolve();
  if (in_qdmsan_hook) {
    return real_ptrace ? real_ptrace(request, pid, addr, data) : -1;
  }
  unsigned long pc = (unsigned long)__builtin_return_address(0);
  in_qdmsan_hook = 1;
  qdmsan_suppress_enter();
  uint64_t h = qdmsan_hash_bytes(data, data ? 256 : 0);
  long ret = real_ptrace ? real_ptrace(request, pid, addr, data) : -1;
  qdmsan_suppress_leave();
  qdmsan_record_libc(pc, h, 0x153);
  qdmsan_record_libc(pc, (unsigned long)(int64_t)ret, 0x53);
  in_qdmsan_hook = 0;
  return ret;
}
