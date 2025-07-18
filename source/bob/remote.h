#ifndef __BOB_REMOTE_H__
#define __BOB_REMOTE_H__

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ModuleHandle;
struct ProcessHandle;

/* -------------------------------------------------------------------- */
/** \name Datablock Definition
 * \{ */

typedef struct RemoteWorker RemoteWorker;

/** \} */

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

/**
 * Install a simple infinite loop in a remote thread.
 * Shellcode that we want to execute will be queued using APC!
 */
struct RemoteWorker *BOB_remote_worker_open(struct ProcessHandle *process, eMomArchitecture architecture);

/**
 * Kill the remote worker and free all the resources!
 */
void BOB_remote_worker_close(struct RemoteWorker *worker);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Execution
 * \{ */

typedef enum eBobArgumentDeref {
	BOB_NODEREF,
	BOB_DEREF,
	BOB_DEREF4,
	BOB_DEREF8,
} eBobArgumentDeref;

void *BOB_remote_write_ex(struct RemoteWorker *worker, const void *buffer, size_t size);
void *BOB_remote_push_ex(struct RemoteWorker *worker, const void *buffer, size_t size);
void BOB_remote_push(struct RemoteWorker *worker, uint64_t arg, eBobArgumentDeref deref);
void *BOB_remote_push_ansi(struct RemoteWorker *worker, const char *buffer);
void *BOB_remote_push_wide(struct RemoteWorker *worker, const wchar_t *buffer);

typedef enum eBobCallConvention {
	BOB_STDCALL,
	BOB_FASTCALL,
	BOB_THISCALL,
	BOB_WIN64,
} eBobCallConvention;

void BOB_remote_begin64(struct RemoteWorker *worker);
void BOB_remote_call(struct RemoteWorker *worker, eBobCallConvention convention, const void *procedure);
void BOB_remote_notify(struct RemoteWorker *worker);
void BOB_remote_end64(struct RemoteWorker *worker);
// Save the last return value register into an internal buffer array at the specified index
void BOB_remote_save(struct RemoteWorker *worker, int index);
uint64_t BOB_remote_exec(struct RemoteWorker *worker, void *argument);
uint64_t BOB_remote_saved(struct RemoteWorker *worker, int index);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Common Routines
 * \{ */

bool BOB_remote_build_manifest(struct RemoteWorker *worker, const void *manifest, size_t size);
bool BOB_remote_bind_manifest(struct RemoteWorker *worker);
bool BOB_remote_unbind_manifest(struct RemoteWorker *worker);

bool BOB_remote_bind_local_manifest(struct RemoteWorker *worker, uint64_t *cookie);
bool BOB_remote_unbind_local_manifest(struct RemoteWorker *worker, uint64_t cookie);

bool BOB_remote_build_cookie(struct RemoteWorker *worker, void *cookieptr);
bool BOB_remote_build_seh(struct RemoteWorker *worker, struct ModuleHandle *handle, void *seh, size_t count);
bool BOB_remote_build_tls(struct RemoteWorker *worker, struct ModuleHandle *handle);
void *BOB_remote_load_dep(struct RemoteWorker *worker, struct ModuleHandle *handle);
bool BOB_remote_call_entry(struct RemoteWorker *worker, struct ModuleHandle *handle);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Queries
 * \{ */

struct ThreadHandle *BOB_remote_thread(struct RemoteWorker *worker);

/** \} */

#ifdef __cplusplus
}
#endif

#endif
