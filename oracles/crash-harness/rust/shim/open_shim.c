/* AEGIS crash shim, variadic open* entry points (companion to src/lib.rs; preload BEFORE libaegis_crash_shim.so).
 * Stable Rust cannot define C-variadic functions, and rustc 1.99 rejects a fixed-arity definition of std's runtime
 * `open` symbol, so these four live here. Each performs the real call and hands the result to the Rust shim. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
extern int aegis_shim_after_open(int dirfd, const char *path, int flags, int rfd);
#define MODE_ARG(flags, m) mode_t m = 0; if ((flags) & (O_CREAT | O_TMPFILE)) { va_list ap; va_start(ap, flags); m = va_arg(ap, mode_t); va_end(ap); }
#define REAL(T, name) static T real_##name; if (!real_##name) { real_##name = (T)dlsym(RTLD_NEXT, #name); if (!real_##name) abort(); }
typedef int (*open_t)(const char *, int, ...);
typedef int (*openat_t)(int, const char *, int, ...);
int open(const char *p, int flags, ...) { MODE_ARG(flags, m); REAL(open_t, open); return aegis_shim_after_open(AT_FDCWD, p, flags, real_open(p, flags, m)); }
int open64(const char *p, int flags, ...) { MODE_ARG(flags, m); REAL(open_t, open64); return aegis_shim_after_open(AT_FDCWD, p, flags, real_open64(p, flags, m)); }
int openat(int d, const char *p, int flags, ...) { MODE_ARG(flags, m); REAL(openat_t, openat); return aegis_shim_after_open(d, p, flags, real_openat(d, p, flags, m)); }
int openat64(int d, const char *p, int flags, ...) { MODE_ARG(flags, m); REAL(openat_t, openat64); return aegis_shim_after_open(d, p, flags, real_openat64(d, p, flags, m)); }
