#ifndef NATIVE_H
#define NATIVE_H

/** This is the platform native include, fine to include windows.h here, UNIX not supported anyway! */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

#define MIN_ADDRESS 0x10000
#define MAX_ADDRESS 0x7FFFFFFEFFFF

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------- */
/** \name Windows NT Exported Methods
 * \{ */

typedef NTSTATUS(NTAPI *fnNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);
typedef NTSTATUS(NTAPI *fnNtQueryVirtualMemory)(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN INT MemoryInformationClass, OUT PVOID MemoryInformation, IN SIZE_T MemoryInformationLength, OUT PSIZE_T ReturnLength);
typedef NTSTATUS(NTAPI *fnNtCreateThreadEx)(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN HANDLE ProcessHandle, IN LPVOID Routine, IN PVOID Argument OPTIONAL, IN ULONG CreateFlags, IN SIZE_T ZeroBits, IN SIZE_T StackSize, IN SIZE_T MaximumStackSize, IN LPVOID AttributeList OPTIONAL);
typedef NTSTATUS(NTAPI *fnNtCreateEvent)(OUT HANDLE EventHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN INT EventType, IN BOOLEAN InitialState);

extern fnNtQueryInformationProcess _NtQueryInformationProcess;
extern fnNtQueryVirtualMemory _NtQueryVirtualMemory;
extern fnNtCreateThreadEx _NtCreateThreadEx;
extern fnNtCreateEvent _NtCreateEvent;

/** \} */

void BOB_native_last_error_describe();

/**
 * This module leverages some functions that are claimed to become depracated and replaced by the Toolhelp API.
 * This method loads the no longer supported functions from the Windows NT dll.
 */
void BOB_native_init();
/** Plain cleanup of loaded modules and memory allocations. */
void BOB_native_exit();

#ifdef __cplusplus
}
#endif

#endif
