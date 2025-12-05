#include "MEM_guardedalloc.h"

#define ASMJIT_STATIC
#include "core.h"
#include "x86.h"
#include "a64.h"

#include "defines.h"
#include "mom.h"
#include "remote.h"

/* -------------------------------------------------------------------- */
/** \name Internal
 * \{ */

class RemoteWorkerImplementation {
	struct Header {
		uint64_t manifest;
		uint64_t cookie;
		uint64_t saved[8];
	};

	struct Param {
		struct Param *prev, *next;

		uint64_t imm;
		eBobArgumentDeref ref; // More like deref but I like to keep names equal-length!
	};

protected:
	static void begin_call64(asmjit::x86::Assembler &ASM) {
		if (!ASM.is64Bit()) {
			return;
		}

		ASM.sub(asmjit::x86::rsp, asmjit::imm(0x28));

		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x8), asmjit::x86::rcx);  // MOV [RSP + 0x08], RCX
		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x10), asmjit::x86::rdx); // MOV [RSP + 0x10], RDX
		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x18), asmjit::x86::r8);  // MOV [RSP + 0x18], R8
		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x20), asmjit::x86::r9);  // MOV [RSP + 0x20], R9
	}

	static void end_call64(asmjit::x86::Assembler &ASM) {
		if (!ASM.is64Bit()) {
			return;
		}

		ASM.mov(asmjit::x86::rcx, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x08)); // MOV RCX, QWORD PTR [RSP + 0x08]
		ASM.mov(asmjit::x86::rdx, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x10)); // MOV RDX, QWORD PTR [RSP + 0x10]
		ASM.mov(asmjit::x86::r8, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x18));  // MOV R8 , QWORD PTR [RSP + 0x18]
		ASM.mov(asmjit::x86::r9, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x20));  // MOV R9 , QWORD PTR [RSP + 0x20]

		ASM.add(asmjit::x86::rsp, asmjit::imm(0x28));
		ASM.ret();
	}

	static void store(asmjit::x86::Assembler &ASM, const asmjit::x86::Gp &reg, Param *param) {
		switch (param->ref) {
			case BOB_DEREF: {
				if (ASM.is64Bit()) {
					ASM.mov(asmjit::x86::rax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::qword_ptr(asmjit::x86::rax));
				} else {
					ASM.mov(asmjit::x86::eax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::dword_ptr(asmjit::x86::eax));
				}
			} break;
			case BOB_DEREF4: {
				if (ASM.is64Bit()) {
					ASM.mov(asmjit::x86::rax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::dword_ptr(asmjit::x86::rax));
				} else {
					ASM.mov(asmjit::x86::eax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::dword_ptr(asmjit::x86::eax));
				}
			} break;
			case BOB_DEREF8: {
				if (ASM.is64Bit()) {
					ASM.mov(asmjit::x86::rax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::qword_ptr(asmjit::x86::rax));
				} else {
					// ASM.mov(asmjit::x86::eax, param->imm);
					// ASM.mov(reg, asmjit::x86::qword_ptr(asmjit::x86::eax));
				}
			} break;
			default: {
				ASM.mov(reg, asmjit::imm(param->imm));
			} break;
		}
	}

	static void push(asmjit::x86::Assembler &ASM, Param *param) {
		if (ASM.is64Bit()) {
			store(ASM, asmjit::x86::rbx, param);
			ASM.push(asmjit::x86::rbx);
		} else {
			store(ASM, asmjit::x86::ebx, param);
			ASM.push(asmjit::x86::ebx);
		}
	}

	void call(asmjit::x86::Assembler &ASM, const void *procedure) {
		size_t nparams = LIB_listbase_count(&this->params);

		if (ASM.is64Bit()) {
			size_t diff = (nparams + 4) * sizeof(uintptr_t) + sizeof(uintptr_t); // args + return
			diff = (diff + 0x10) & ~0xF;

			ASM.sub(asmjit::x86::rsp, asmjit::imm(diff)); // SUB RSP, diff
			Param *p = static_cast<Param *>(this->params.first);
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // RCX
				store(ASM, asmjit::x86::rcx, p);
				MEM_freeN(p);
			}
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // RDX
				store(ASM, asmjit::x86::rdx, p);
				MEM_freeN(p);
			}
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // R8
				store(ASM, asmjit::x86::r8, p);
				MEM_freeN(p);
			}
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // R9
				store(ASM, asmjit::x86::r9, p);
				MEM_freeN(p);
			}

			while ((p = static_cast<Param *>(LIB_poptail(&this->params)))) {
				push(ASM, p);
				MEM_freeN(p);
			}

			ASM.mov(asmjit::x86::r13, asmjit::imm(procedure));
			ASM.call(asmjit::x86::r13);
			ASM.add(asmjit::x86::rsp, asmjit::imm(diff)); // ADD RSP, diff
		} else {
			if (nparams < 2) {
				Param *p = static_cast<Param *>(this->params.first);
				if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // EDX
					store(ASM, asmjit::x86::edx, p);
					MEM_freeN(p);
				}

				stdcall(ASM, procedure);
			}

			Param *p = static_cast<Param *>(this->params.first);
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // EDX
				store(ASM, asmjit::x86::edx, p);
				MEM_freeN(p);
			}
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // EAX
				store(ASM, asmjit::x86::eax, p);
				MEM_freeN(p);
			}

			while ((p = static_cast<Param *>(LIB_poptail(&this->params)))) {
				push(ASM, p);
				MEM_freeN(p);
			}

			ASM.mov(asmjit::x86::ebx, asmjit::imm(procedure));
			ASM.call(asmjit::x86::ebx);
		}

		LIB_listbase_clear(&this->params);
	}

	void stdcall(asmjit::x86::Assembler &ASM, const void *procedure) {
		Param *p;
		while ((p = static_cast<Param *>(LIB_poptail(&this->params)))) {
			push(ASM, p);
			MEM_freeN(p);
		}

		ASM.mov(asmjit::x86::eax, asmjit::imm(procedure));
		ASM.call(asmjit::x86::eax);

		LIB_listbase_clear(&this->params);
	}

	void fastcall(asmjit::x86::Assembler &ASM, const void *procedure) {
		// WIN64 call convention and fastcall call convention is the same thing!
		call(ASM, procedure);

		LIB_listbase_clear(&this->params);
	}

	void thiscall(asmjit::x86::Assembler &ASM, const void *procedure) {
		Param *p = static_cast<Param *>(this->params.first);
		if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // ECX
			store(ASM, asmjit::x86::ecx, p);
			MEM_freeN(p);
		}

		while ((p = static_cast<Param *>(LIB_poptail(&this->params)))) {
			push(ASM, p);
			MEM_freeN(p);
		}

		ASM.mov(asmjit::x86::eax, asmjit::imm(procedure));
		ASM.call(asmjit::x86::eax);

		LIB_listbase_clear(&this->params);
	}

public:
	RemoteWorkerImplementation(ProcessHandle *process, eMomArchitecture architecture) : process(process), asmruntime(), codeholder(), architecture(architecture), thread(NULL) {
		switch (architecture) {
			case MOM_ARCHITECTURE_AMD32: {
				this->codeholder.init(asmjit::Environment(asmjit::Arch::kX86), asmruntime.cpuFeatures());
			} break;
			case MOM_ARCHITECTURE_AMD64:
			default: {
				this->codeholder.init(asmjit::Environment(asmjit::Arch::kX64), asmruntime.cpuFeatures());
			} break;
		}

		this->loop = MOM_process_allocate(process, NULL, 0x001000, MOM_PROTECT_R | MOM_PROTECT_W | MOM_PROTECT_E);	// 4KB
		this->code = MOM_process_allocate(process, NULL, 0x001000, MOM_PROTECT_R | MOM_PROTECT_W | MOM_PROTECT_E);	// 4KB
		this->user = MOM_process_allocate(process, NULL, 0x400000, MOM_PROTECT_R | MOM_PROTECT_W);					// 4MB
		this->offset = sizeof(Header);

		LIB_listbase_clear(&this->params);
	}

	~RemoteWorkerImplementation() {
		/**
		 * Because when the event is triggered the stack has not been fully cleared yet,
		 * we need to wait a little bit longer so that the RSP can be re-aligned again!
		 */
		MOM_event_wait(this->evtlocal, 1);
		MOM_event_close(this->evtlocal);
		MOM_thread_terminate(this->thread, 0);
		MOM_thread_close(this->thread);

		MOM_process_free(process, this->loop);
		MOM_process_free(process, this->code);
		MOM_process_free(process, this->user);
	}

	void begin_call64() {
		if (this->architecture != MOM_ARCHITECTURE_AMD64) {
			return;
		}

		asmjit::x86::Assembler ASM(&this->codeholder);

		this->begin_call64(ASM);
	}

	void end_call64() {
		if (this->architecture != MOM_ARCHITECTURE_AMD64) {
			return;
		}

		asmjit::x86::Assembler ASM(&this->codeholder);

		this->end_call64(ASM);
	}

	void call(const void *procedure) {
		asmjit::x86::Assembler ASM(&this->codeholder);

		this->call(ASM, procedure);
	}

	void stdcall(const void *procedure) {
		asmjit::x86::Assembler ASM(&this->codeholder);

		this->stdcall(ASM, procedure);
	}

	void fastcall(const void *procedure) {
		asmjit::x86::Assembler ASM(&this->codeholder);

		this->fastcall(ASM, procedure);
	}

	void thiscall(const void *procedure) {
		asmjit::x86::Assembler ASM(&this->codeholder);

		this->thiscall(ASM, procedure);
	}

	void int3() {
		asmjit::x86::Assembler ASM(&this->codeholder);

		ASM.int3();
	}

	void push(uint64_t imm, eBobArgumentDeref ref) {
		Param *p = static_cast<Param *>(MEM_mallocN(sizeof(Param), "Param"));

		p->imm = imm;
		p->ref = ref;

		LIB_addtail(&this->params, p);
	}

	void *write(const void *buffer, size_t size) {
		void *address = POINTER_OFFSET(this->user, this->offset);
		if (buffer) {
			MOM_process_write(this->process, address, buffer, size);
		}
		this->offset = this->offset + size;
		return address;
	}

	bool init() {
		// !CAUTION! Different codeholder within this context for important reasons!
		asmjit::CodeHolder codeholder;
		codeholder.init(this->codeholder.environment(), this->asmruntime.cpuFeatures());

		if (!(this->evtlocal = MOM_event_open(NULL))) {
			return false;
		}
		if (!(this->evtremote = (void *)MOM_event_share(this->evtlocal, this->process))) {
			return false;
		}

		ModuleHandle *ntdll = MOM_process_module_find_by_name(this->process, "ntdll.dll");
		ModuleExport *ntdelayexecution = MOM_module_export_find_by_name(ntdll, "NtDelayExecution");
		void *_NtDelayExecution = MOM_module_export_physical(ntdll, ntdelayexecution);

		asmjit::x86::Assembler ASM(&codeholder);

		if (ASM.is64Bit()) {
			begin_call64(ASM);
		}

		asmjit::Label loop = ASM.newLabel();
		ASM.bind(loop);
		{
			uint64_t delay;
			delay = -10 * 1000 * 5;
			push(0x01, BOB_NODEREF);
			push((uint64_t)write(&delay, sizeof(delay)), BOB_NODEREF);
			call(ASM, _NtDelayExecution);
		}
		ASM.jmp(loop);
		if (ASM.is64Bit()) {
			end_call64(ASM);
		}

		ASM.ret();

		asmjit::Section *section = codeholder.sectionById(0);
		asmjit::CodeBuffer buffer = section->buffer();

		if (!MOM_process_write(this->process, this->loop, buffer.data(), buffer.size())) {
			return false;
		}

		this->thread = MOM_thread_spawn(this->process, this->loop, NULL);

		return true;
	}

	void *make() {
		for (size_t index = 0; index < this->codeholder.sectionCount(); index++) {
			asmjit::Section *section = this->codeholder.sectionById(index);
			if (section) {
				asmjit::CodeBuffer buffer = section->buffer();

				/*
				 * We should handle better multiple sections and not just write the last one!
				 */
				if (!MOM_process_write(this->process, this->code, buffer.data(), buffer.size())) {
					return NULL;
				}
			}
		}

		this->codeholder.reset(asmjit::ResetPolicy::kHard);
		this->codeholder.init(this->asmruntime.environment(), this->asmruntime.cpuFeatures());

		return this->code;
	}

	ProcessHandle *host() const {
		return this->process;
	}

	ThreadHandle *worker() const {
		return this->thread;
	}

	void *ptrsave(size_t index) const {
		return POINTER_OFFSET(this->user, offsetof(Header, saved[index]));
	}

	void *ptrcookie(void) const {
		return POINTER_OFFSET(this->user, offsetof(Header, cookie));
	}

	void *ptrmanifest(void) const {
		return POINTER_OFFSET(this->user, offsetof(Header, manifest));
	}

	void save(int index) {
		asmjit::x86::Assembler ASM(&this->codeholder);

		/**
		 * Write the current return value into internal data.
		 */
		void *ret = this->ptrsave(index);
		if (ASM.is64Bit()) {
			ASM.mov(asmjit::x86::rdx, asmjit::imm(reinterpret_cast<uint64_t>(ret)));
			ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rdx), asmjit::x86::rax);
		} else {
			ASM.mov(asmjit::x86::edx, asmjit::imm(POINTER_AS_UINT(ret)));
			ASM.mov(asmjit::x86::dword_ptr(asmjit::x86::edx), asmjit::x86::eax);
		}
	}

	void notify() {
		asmjit::x86::Assembler ASM(&this->codeholder);

		ModuleHandle *kernel32 = MOM_process_module_find_by_name(this->process, "kernel32.dll");
		ModuleExport *setevent = MOM_module_export_find_by_name(kernel32, "SetEvent");
		void *_SetEvent = MOM_module_export_physical(kernel32, setevent);

		if (ASM.is64Bit()) {
			ASM.mov(asmjit::x86::rcx, asmjit::imm(this->evtremote)); // rcx = HANDLE
			ASM.mov(asmjit::x86::rax, asmjit::imm(_SetEvent));       // rax = &SetEvent
			ASM.call(asmjit::x86::rax);                              // call SetEvent(rcx)
		} else {
			// On x86, SetEvent uses stdcall: push HANDLE, then call
			ASM.push(asmjit::imm(this->evtremote));            // push HANDLE
			ASM.mov(asmjit::x86::eax, asmjit::imm(_SetEvent)); // eax = &SetEvent
			ASM.call(asmjit::x86::eax);                        // call SetEvent
		}
	}

	uint64_t invoke(void *argument) {
		void *code;
		if ((code = this->make())) {
			// fprintf(stdout, "[Remote] Thread ID %d\n", MOM_thread_identifier(thread));
			// fprintf(stdout, "[Remote] Thread TEB 0x%p\n", MOM_thread_teb(thread));
			MOM_thread_queue_apc(thread, code, argument);
			if (!MOM_event_wait(evtlocal, -1)) {
				fprintf(stderr, "[Error] shellcode timedout!\n");
				return 0;
			}
			MOM_event_reset(this->evtlocal);

			uint64_t ret;
			MOM_process_read(this->process, this->ptrsave(0), &ret, sizeof(ret));
			return ret;
		}
		return 0;
	}

	eMomArchitecture arch() const {
		return this->architecture;
	}

	uintptr_t set_local_manifest(uintptr_t manifest) {
		return this->manifest = manifest;
	}
	uintptr_t get_local_manifest() const {
		return manifest;
	}

private:
	EventHandle *evtlocal = NULL;
	ProcessHandle *process = NULL;
	ThreadHandle *thread = NULL;
	eMomArchitecture architecture;

	asmjit::JitRuntime asmruntime;
	asmjit::CodeHolder codeholder;

	void *evtremote = NULL;

	void *loop = NULL;
	void *code = NULL;
	void *user = NULL;

	uintptr_t offset = 0;
	uintptr_t manifest = 0;

	ListBase params;
};

RemoteWorker *wrap(class RemoteWorkerImplementation *self) {
	return reinterpret_cast<RemoteWorker *>(self);
}
const RemoteWorker *wrap(const class RemoteWorkerImplementation *self) {
	return reinterpret_cast<const RemoteWorker *>(self);
}

RemoteWorkerImplementation *unwrap(struct RemoteWorker *self) {
	return reinterpret_cast<RemoteWorkerImplementation *>(self);
}
const RemoteWorkerImplementation *unwrap(const struct RemoteWorker *self) {
	return reinterpret_cast<const RemoteWorkerImplementation *>(self);
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

RemoteWorker *BOB_remote_worker_open(ProcessHandle *process, eMomArchitecture architecture) {
	RemoteWorkerImplementation *self = MEM_new<RemoteWorkerImplementation>("RemoteWorker", process, architecture);
	if (!self->init()) {
		BOB_remote_worker_close(wrap(self));
		self = nullptr;
	}
	return wrap(self);
}

void BOB_remote_worker_close(RemoteWorker *worker) {
	MEM_delete<RemoteWorkerImplementation>(unwrap(worker));
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Internal
 * \{ */

void *BOB_remote_write_ex(RemoteWorker *worker, const void *buffer, size_t size) {
	return unwrap(worker)->write(buffer, size);
}

void *BOB_remote_push_ex(RemoteWorker *worker, const void *buffer, size_t size) {
	void *address = BOB_remote_write_ex(worker, buffer, size);
	BOB_remote_push(worker, reinterpret_cast<uint64_t>(address), BOB_NODEREF);
	return address;
}

void BOB_remote_push(RemoteWorker *worker, uint64_t arg, eBobArgumentDeref deref) {
	unwrap(worker)->push(arg, deref);
}

void *BOB_remote_push_ansi(RemoteWorker *worker, const char *buffer) {
	return BOB_remote_push_ex(worker, buffer, sizeof(char) * (strlen(buffer) + 1));
}

void *BOB_remote_push_wide(RemoteWorker *worker, const wchar_t *buffer) {
	return BOB_remote_push_ex(worker, buffer, sizeof(wchar_t) * (wcslen(buffer) + 1));
}

void BOB_remote_begin64(RemoteWorker *worker) {
	unwrap(worker)->begin_call64();
}

void BOB_remote_call(RemoteWorker *worker, eBobCallConvention convention, const void *procedure) {
	if (unwrap(worker)->arch() == MOM_ARCHITECTURE_AMD64) {
		convention = BOB_WIN64;
	}

	switch (convention) {
		case BOB_WIN64: {
			unwrap(worker)->call(procedure);
		} break;
		case BOB_FASTCALL: {
			unwrap(worker)->fastcall(procedure);
		} break;
		case BOB_STDCALL: {
			unwrap(worker)->stdcall(procedure);
		} break;
		case BOB_THISCALL: {
			unwrap(worker)->thiscall(procedure);
		} break;
	}
}

void BOB_remote_notify(RemoteWorker *worker) {
	unwrap(worker)->notify();
}

void BOB_remote_end64(RemoteWorker *worker) {
	unwrap(worker)->end_call64();
}

uint64_t BOB_remote_exec(RemoteWorker *remote, void *argument) {
	return unwrap(remote)->invoke(argument);
}

void BOB_remote_save(RemoteWorker *worker, int index) {
	unwrap(worker)->save(index);
}

uint64_t BOB_remote_saved(RemoteWorker *worker, int index) {
	uint64_t ret;

	void *ptr = unwrap(worker)->ptrsave(index);
	MOM_process_read(unwrap(worker)->host(), ptr, &ret, sizeof(ret));
	return ret;
}

ThreadHandle *BOB_remote_thread(RemoteWorker *worker) {
	return unwrap(worker)->worker();
}

void BOB_remote_breakpoint(RemoteWorker *worker) {
	unwrap(worker)->int3();
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Common Routines
 * \{ */

#ifdef WIN32

#include <windows.h>
#include <winternl.h>
#include <sysinfoapi.h>
#include <versionhelpers.h>
#include <tchar.h>

void *BOB_remote_ntdll_symbol(RemoteWorker *vworker, const unsigned char pattern[], const size_t size, const size_t offset) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	ModuleHandle *ntdll = MOM_process_module_find_by_name(worker->host(), "ntdll.dll");
	ListBase sections = MOM_module_sections(ntdll);
	LISTBASE_FOREACH(ModuleSection *, section, &sections) {
		void *begin = MOM_module_section_logical(ntdll, section);
		void *end = POINTER_OFFSET(MOM_module_section_logical(ntdll, section), MOM_module_section_size(ntdll, section));

		if (strcmp(MOM_module_section_name(ntdll, section), ".text") == 0) {
			for (void *ptr = POINTER_OFFSET(begin, 0); POINTER_OFFSET(ptr, offset + size) != end; ptr = POINTER_OFFSET(ptr, 1)) {
				if (memcmp(POINTER_OFFSET(ptr, offset), pattern, size) == 0) {
					if (((const unsigned char *)ptr)[-1] != (unsigned char)'\xcc' && ((const unsigned char *)ptr)[-1] != (unsigned char)'\xc3') {
						continue;
					}
					
					bool invalid = false;
					for (void *itr = POINTER_OFFSET(ptr, 0); itr != POINTER_OFFSET(ptr, offset); itr = POINTER_OFFSET(itr, 1)) {
						if (((const unsigned char *)itr)[0] == (unsigned char)'\xcc') {
							invalid |= true;
						}
					}

					if (!invalid) {
						return POINTER_OFFSET(MOM_module_section_physical(ntdll, section), (const uint8_t *)ptr - (const uint8_t *)begin);
					}
				}
			}
			break;
		}
	}

	return NULL;
}

void *BOB_remote_ntdll_symbol_ex(RemoteWorker *vworker, const unsigned char pattern[], const size_t size, const size_t offset, const size_t operandoffset, const size_t instructionsize) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	ModuleHandle *ntdll = MOM_process_module_find_by_name(worker->host(), "ntdll.dll");
	ListBase sections = MOM_module_sections(ntdll);
	LISTBASE_FOREACH(ModuleSection *, section, &sections) {
		void *begin = MOM_module_section_logical(ntdll, section);
		void *end = POINTER_OFFSET(MOM_module_section_logical(ntdll, section), MOM_module_section_size(ntdll, section));

		if (strcmp(MOM_module_section_name(ntdll, section), ".text") == 0) {
			for (void *ptr = POINTER_OFFSET(begin, 0); POINTER_OFFSET(ptr, offset + size) != end; ptr = POINTER_OFFSET(ptr, 1)) {
				if (memcmp(POINTER_OFFSET(ptr, offset), pattern, size) == 0) {
					int32_t displacement;
					memcpy(&displacement, POINTER_OFFSET(ptr, operandoffset), sizeof(displacement));
					
					ptr = POINTER_OFFSET(ptr, instructionsize + displacement);
					return POINTER_OFFSET(MOM_module_section_physical(ntdll, section), (const uint8_t *)ptr - (const uint8_t *)begin);
				}
			}
			break;
		}
	}

	return NULL;
}

void *BOB_remote_write_manifest(RemoteWorker *worker, const void *vmanifest, size_t size) {
	TCHAR directory[MAX_PATH], filename[MAX_PATH];
	GetTempPath(ARRAYSIZE(directory), directory);
	if (GetTempFileName(directory, _T("ImageManifest"), 0, filename) == 0) {
		return NULL;
	}

	HANDLE fpout = CreateFile(filename, FILE_GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
	if (!fpout) {
		return NULL;
	}
	DWORD write;
	if (!WriteFile(fpout, vmanifest, size, &write, NULL)) {
		CloseHandle(fpout);
		return NULL;
	}
	CloseHandle(fpout);

	ACTCTX context;
	memset(&context, 0, sizeof(ACTCTX));
	context.cbSize = sizeof(ACTCTX);
	context.lpSource = filename;

	if (!unwrap(worker)->set_local_manifest((uintptr_t)CreateActCtx(&context))) {
		return NULL;
	}

	return BOB_remote_write_ex(worker, filename, sizeof(filename));
}

bool BOB_remote_build_manifest(RemoteWorker *vworker, const void *vmanifest, size_t size) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	void *manifest = NULL;
	if (!MOM_process_read(worker->host(), worker->ptrmanifest(), &manifest, sizeof(manifest))) {
		return false;
	}

	if (!manifest) {
		ACTCTX context;
		memset(&context, 0, sizeof(ACTCTX));
		context.cbSize = sizeof(ACTCTX);
		context.lpSource = (LPCSTR)BOB_remote_write_manifest(vworker, vmanifest, size);

		ModuleHandle *kernel32 = MOM_process_module_find_by_name(worker->host(), "kernel32.dll");
		ModuleExport *createactctx = MOM_module_export_find_by_name(kernel32, STRINGIFY(CreateActCtx));
		void *_CreateActCtx = MOM_module_export_physical(kernel32, createactctx);

		BOB_remote_begin64(vworker);
		BOB_remote_push_ex(vworker, &context, sizeof(context));
		BOB_remote_call(vworker, BOB_WIN64, _CreateActCtx);
		BOB_remote_save(vworker, 0);
		BOB_remote_notify(vworker);
		BOB_remote_end64(vworker);

		if (!(manifest = (HANDLE)BOB_remote_exec(vworker, NULL))) {
			return false;
		}

		if (!MOM_process_write(worker->host(), worker->ptrmanifest(), &manifest, sizeof(manifest))) {
			return false;
		}
	}

	return true;
}

bool BOB_remote_bind_manifest(RemoteWorker *vworker) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	void *manifest = NULL;
	if (!MOM_process_read(worker->host(), worker->ptrmanifest(), &manifest, sizeof(manifest))) {
		return false;
	}

	if (!manifest) {
		return true;
	}

	ModuleHandle *ntdll = MOM_process_module_find_by_name(worker->host(), "ntdll.dll");
	ModuleExport *activateactctx = MOM_module_export_find_by_name(ntdll, "RtlActivateActivationContext");
	void *_ActivateActCtx = MOM_module_export_physical(ntdll, activateactctx);

	BOB_remote_push(vworker, (uint64_t)0, BOB_NODEREF);
	BOB_remote_push(vworker, (uint64_t)manifest, BOB_NODEREF);
	BOB_remote_push(vworker, (uint64_t)worker->ptrcookie(), BOB_NODEREF);
	BOB_remote_call(vworker, BOB_WIN64, _ActivateActCtx);
	BOB_remote_save(vworker, 1);

	return true;
}

bool BOB_remote_unbind_manifest(RemoteWorker *vworker) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	void *manifest = NULL;
	if (!MOM_process_read(worker->host(), worker->ptrmanifest(), &manifest, sizeof(manifest))) {
		return false;
	}

	if (!manifest) {
		return true;
	}

	ModuleHandle *ntdll = MOM_process_module_find_by_name(worker->host(), "ntdll.dll");
	ModuleExport *deactivateactctx = MOM_module_export_find_by_name(ntdll, "RtlDeactivateActivationContext");
	void *_DeactivateActCtx = MOM_module_export_physical(ntdll, deactivateactctx);

	BOB_remote_push(vworker, 0, BOB_NODEREF);
	BOB_remote_push(vworker, (uint64_t)worker->ptrcookie(), BOB_DEREF);
	BOB_remote_call(vworker, BOB_WIN64, _DeactivateActCtx);
	BOB_remote_save(vworker, 2);

	return true;
}

bool BOB_remote_bind_local_manifest(RemoteWorker *worker, uint64_t *cookie) {
	if (unwrap(worker)->get_local_manifest()) {
		return ActivateActCtx((HANDLE)unwrap(worker)->get_local_manifest(), cookie);
	}
	return true;
}

bool BOB_remote_unbind_local_manifest(RemoteWorker *worker, uint64_t cookie) {
	if (unwrap(worker)->get_local_manifest()) {
		return DeactivateActCtx(0, cookie);
	}
	return true;
}

bool BOB_remote_build_cookie(RemoteWorker *vworker, void *cookieptr) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	if (cookieptr) {
		FILETIME time = {};
		LARGE_INTEGER perfomance = {{}};

		uintptr_t cookie = 0;

		cookie = MOM_process_identifier(worker->host()) ^ MOM_thread_identifier(worker->worker()) ^ reinterpret_cast<uintptr_t>(&cookie);

		GetSystemTimeAsFileTime(&time);
		QueryPerformanceCounter(&perfomance);

		cookie ^= *reinterpret_cast<uintptr_t *>(&time);
		cookie ^= (perfomance.QuadPart << 32) ^ perfomance.QuadPart;
		cookie &= 0xFFFFFFFFFFFF;

		if (cookie == 0x2B992DDFA232) {
			cookie++;
		}

		if (!MOM_process_write(worker->host(), cookieptr, &cookie, sizeof(cookie))) {
			fprintf(stderr, "[Error] Cookie failed.\n");
			return false;
		}
	}

	return true;
}

// taken from CRT include <Ehdata.h>
#	define EH_MAGIC_NUMBER1 0x19930520
#	define EH_PURE_MAGIC_NUMBER1 0x01994000
#	define EH_EXCEPTION_NUMBER ('msc' | 0xE0000000)

/* clang-format off */

uint8_t VEH32[] = {
	0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x18, 0x60, 0xB8, 0x7A, 0xDA, 0xAD, 0xDE, 0x89, 0x45, 0xF4, 0xB8, 
	0xD2, 0xC0, 0xAD, 0xDE, 0x89, 0x45, 0xEC, 0x64, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x64, 0x8B, 
	0x0D, 0x30, 0x00, 0x00, 0x00, 0x89, 0x5D, 0xF8, 0x8B, 0x81, 0xA4, 0x00, 0x00, 0x00, 0x83, 0xF8, 
	0x06, 0x72, 0x09, 0x83, 0xB9, 0xA8, 0x00, 0x00, 0x00, 0x02, 0x73, 0x11, 0x83, 0xF8, 0x0A, 0x73, 
	0x0C, 0x8B, 0x7D, 0xF4, 0xC6, 0x45, 0xFF, 0x00, 0x83, 0xC7, 0x0C, 0xEB, 0x0A, 0x8B, 0x7D, 0xF4, 
	0xC6, 0x45, 0xFF, 0x01, 0x83, 0xC7, 0x10, 0x8B, 0x45, 0xEC, 0x89, 0x7D, 0xE8, 0x85, 0xC0, 0x74, 
	0x07, 0x6A, 0x00, 0xFF, 0xD0, 0x8B, 0x45, 0xEC, 0x85, 0xDB, 0x0F, 0x84, 0xEA, 0x00, 0x00, 0x00, 
	0x83, 0xFB, 0xFF, 0x0F, 0x84, 0xDE, 0x00, 0x00, 0x00, 0x83, 0x3B, 0xFF, 0x0F, 0x84, 0xD5, 0x00, 
	0x00, 0x00, 0x8B, 0x45, 0xF4, 0x33, 0xF6, 0x89, 0x75, 0xF0, 0x39, 0x30, 0x0F, 0x86, 0xB5, 0x00, 
	0x00, 0x00, 0x83, 0xC7, 0x04, 0x8B, 0x4B, 0x04, 0x8B, 0x17, 0x3B, 0xCA, 0x0F, 0x82, 0x8E, 0x00, 
	0x00, 0x00, 0x8B, 0x47, 0x04, 0x03, 0xC2, 0x3B, 0xC8, 0x0F, 0x87, 0x81, 0x00, 0x00, 0x00, 0x80, 
	0x7D, 0xFF, 0x00, 0x74, 0x08, 0x85, 0xF6, 0x0F, 0x84, 0x8A, 0x00, 0x00, 0x00, 0xFF, 0x77, 0xFC, 
	0xB8, 0xDE, 0xC0, 0xAD, 0xDE, 0xFF, 0xD0, 0x8B, 0xD8, 0x8B, 0xCB, 0x85, 0xDB, 0x74, 0x5E, 0x8D, 
	0xB3, 0x00, 0x04, 0x00, 0x00, 0x3B, 0xCE, 0x73, 0x54, 0x8B, 0x11, 0x85, 0xD2, 0x74, 0x13, 0x8B, 
	0x07, 0x03, 0xC2, 0x8B, 0x55, 0xF8, 0x3B, 0x42, 0x04, 0x74, 0x42, 0x83, 0xC1, 0x04, 0x75, 0xE5, 
	0xEB, 0x3B, 0x8B, 0x45, 0xF8, 0x8B, 0x40, 0x04, 0x2B, 0x07, 0x89, 0x01, 0xB9, 0x00, 0x00, 0x00, 
	0x00, 0x83, 0x47, 0x08, 0x01, 0x74, 0x26, 0x8B, 0x47, 0x08, 0x48, 0x3B, 0xC1, 0x76, 0x18, 0x90, 
	0x8B, 0x74, 0x83, 0xFC, 0x8B, 0x14, 0x83, 0x3B, 0xF2, 0x76, 0x07, 0x89, 0x54, 0x83, 0xFC, 0x89, 
	0x34, 0x83, 0x48, 0x3B, 0xC1, 0x77, 0xE9, 0x41, 0x3B, 0x4F, 0x08, 0x72, 0xDA, 0x8B, 0x5D, 0xF8, 
	0x8B, 0x4D, 0xF0, 0x83, 0xC7, 0x10, 0x8B, 0x45, 0xF4, 0x41, 0x89, 0x4D, 0xF0, 0x8B, 0xF1, 0x3B, 
	0x08, 0x0F, 0x82, 0x4E, 0xFF, 0xFF, 0xFF, 0x8B, 0x1B, 0x8B, 0x7D, 0xE8, 0x89, 0x5D, 0xF8, 0x85, 
	0xDB, 0x0F, 0x85, 0x19, 0xFF, 0xFF, 0xFF, 0x8B, 0x45, 0xEC, 0x85, 0xC0, 0x74, 0x04, 0x6A, 0x01, 
	0xFF, 0xD0, 0x61, 0x8B, 0xE5, 0x5D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00,
};

/*
 * LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo) {
 *     if (ExceptionInfo->ExceptionRecord->ExceptionCode == EH_EXCEPTION_NUMBER) {
 *         ModuleTable* pTable = reinterpret_cast<ModuleTable*>(0xDEADBEEFDEADBEEF);
 *         for (ptr_t i = 0; i < pTable->count; i++) {
 *             if (ExceptionInfo->ExceptionRecord->ExceptionInformation[2] >= pTable->entry[i].base && ExceptionInfo->ExceptionRecord->ExceptionInformation[2] <= pTable->entry[i].base + pTable->entry[i].size) {
 *                 if (ExceptionInfo->ExceptionRecord->ExceptionInformation[0] == EH_PURE_MAGIC_NUMBER1 && ExceptionInfo->ExceptionRecord->ExceptionInformation[3] == 0) {
 *                     ExceptionInfo->ExceptionRecord->ExceptionInformation[0] = (ULONG_PTR)EH_MAGIC_NUMBER1;
 *                     ExceptionInfo->ExceptionRecord->ExceptionInformation[3] = (ULONG_PTR)pTable->entry[i].base;
 *                 }
 *             }
 *         }
 *     }
 *     return EXCEPTION_CONTINUE_SEARCH;
 * }
 */

uint8_t VEH64[] = {
	0x48, 0x83, 0xEC, 0x08, 0x48, 0x8B, 0x01, 0x4C, 0x8B, 0xD9, 0x81, 0x38, 0x63, 0x73, 0x6D, 0xE0, 
    0x0F, 0x85, 0x7C, 0x00, 0x00, 0x00, 0x48, 0x89, 0x1C, 0x24, 0x45, 0x33, 0xC9, 0x48, 0xBB, 0xEF, 
    0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x4C, 0x39, 0x0B, 0x76, 0x5B, 0x48, 0xB8, 0xF7, 0xBE, 
    0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x66, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4D, 0x8B, 0x03, 0x48, 0x8B, 0x10, 0x4D, 0x8B, 0x50, 0x30, 0x4C, 0x3B, 0xD2, 0x72, 0x2C, 0x48, 
    0x03, 0x50, 0x08, 0x4C, 0x3B, 0xD2, 0x77, 0x23, 0x49, 0x81, 0x78, 0x20, 0x00, 0x40, 0x99, 0x01,
    0x75, 0x19, 0x49, 0x83, 0x78, 0x38, 0x00, 0x75, 0x12, 0x49, 0xC7, 0x40, 0x20, 0x20, 0x05, 0x93, 
    0x19, 0x49, 0x8B, 0x13, 0x48, 0x8B, 0x08, 0x48, 0x89, 0x4A, 0x38, 0x49, 0xFF, 0xC1, 0x48, 0x83, 
    0xC0, 0x10, 0x4C, 0x3B, 0x0B, 0x72, 0xB9, 0x33, 0xC0, 0x48, 0x8B, 0x1C, 0x24, 0x48, 0x83, 0xC4, 
    0x08, 0xC3, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x08, 0xC3
};

/* clang-format on */

typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY32 {
	uint32_t ExceptionDirectory;
	uint32_t ImageBase;
	DWORD ImageSize;
	DWORD SizeOfTable;
} RTL_INVERTED_FUNCTION_TABLE_ENTRY32, *PRTL_INVERTED_FUNCTION_TABLE_ENTRY32;

typedef struct _RTL_INVERTED_FUNCTION_TABLE32 {
	ULONG Count;
	ULONG MaxCount;
	ULONG Epoch;
	UCHAR Overflow;
	RTL_INVERTED_FUNCTION_TABLE_ENTRY32 Entries[0x200];
} RTL_INVERTED_FUNCTION_TABLE32, *PRTL_INVERTED_FUNCTION_TABLE32;

typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY64 {
	uint64_t ExceptionDirectory;
	uint64_t ImageBase;
	DWORD ImageSize;
	DWORD SizeOfTable;
} RTL_INVERTED_FUNCTION_TABLE_ENTRY64, *PRTL_INVERTED_FUNCTION_TABLE_ENTRY64;

typedef struct _RTL_INVERTED_FUNCTION_TABLE64 {
	ULONG Count;
	ULONG MaxCount;
	ULONG Epoch;
	UCHAR Overflow;
	RTL_INVERTED_FUNCTION_TABLE_ENTRY64 Entries[0x200];
} RTL_INVERTED_FUNCTION_TABLE64, *PRTL_INVERTED_FUNCTION_TABLE64;

bool BOB_remote_build_seh(RemoteWorker *vworker, ModuleHandle *handle, void *seh, size_t count) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	// C++ Exceptions (Requirements)

	void *_RtlInsertInvertedFunctionTable = NULL;
	void *_LdrpInvertedFunctionTable = NULL;

	// GHIDRA COPY PASTA
	// _RtlInsertInvertedFunctionTable 40 53 48 83 ec 20 8b 1d 84 81 19 00 83 eb 01 74 1d
	// _LdrpInvertedFunctionTable 48 8d 54 24 58 48 8b f9 e8

	switch (worker->arch()) {
		case MOM_ARCHITECTURE_AMD64: {
			if (!_RtlInsertInvertedFunctionTable || !_LdrpInvertedFunctionTable) {
				// fprintf(stdout, "Using Win11 21H2 pattern for RtlInsertInvertedFunctionTable\n");
				_RtlInsertInvertedFunctionTable = BOB_remote_ntdll_symbol(vworker, (const unsigned char[]) "\x89\x70\x20\x57\x48\x83\xec\x30\x83", 9, 0xc);
				_LdrpInvertedFunctionTable = BOB_remote_ntdll_symbol_ex(vworker, (const unsigned char[]) "\x49\x8b\xe8\x48\x8b\xfa\x0f\x84", 8, 0xF, 0x2, 0x6);
			}
			if (!_RtlInsertInvertedFunctionTable || !_LdrpInvertedFunctionTable) {
				// fprintf(stdout, "Using Win11 21H2 pattern for RtlInsertInvertedFunctionTable\n");
				_RtlInsertInvertedFunctionTable = BOB_remote_ntdll_symbol(vworker, (const unsigned char[]) "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x30\x8B\xDA", 12, 0x0);
				_LdrpInvertedFunctionTable = BOB_remote_ntdll_symbol_ex(vworker, (const unsigned char[]) "\x49\x8b\xe8\x48\x8b\xfa\x0f\x84", 8, 0xF, 0x2, 0x6);
			}
			if (!_RtlInsertInvertedFunctionTable || !_LdrpInvertedFunctionTable) {
				// fprintf(stdout, "Using Win10 20H1 pattern for RtlInsertInvertedFunctionTable\n");
				_RtlInsertInvertedFunctionTable = BOB_remote_ntdll_symbol(vworker, (const unsigned char[]) "\x48\x8d\x54\x24\x58\x48\x8b\xf9\xe8", 9, 0x11);
				_LdrpInvertedFunctionTable = BOB_remote_ntdll_symbol_ex(vworker, (const unsigned char[]) "\x49\x8b\xe8\x48\x8b\xfa\x0f\x84", 8, 0xF, 0x2, 0x6);
			}
		} break;
	}

	if (!_RtlInsertInvertedFunctionTable) {
		fprintf(stderr, "[Error] RtlInsertInvertedFunctionTable not found!\n");
		return false;
	}
	if (!_LdrpInvertedFunctionTable) {
		fprintf(stderr, "[Error] LdrpInvertedFunctionTable not found!\n");
		return false;
	}

	/**
	 * As you probably have already figured out the #LdrpInvertedFunctionTable is a pointer!
	 * MOV EAX,dword ptr [KiUserInvertedFunctionTable]
	 * I mean we literaly YEET it off of this instruction!
	 */
	
	// C++ Exceptions

	switch (worker->arch()) {
		case MOM_ARCHITECTURE_AMD64: {
			RTL_INVERTED_FUNCTION_TABLE64 KiUserInvertedFunctionTable;
			if (!MOM_process_read(worker->host(), _LdrpInvertedFunctionTable, &KiUserInvertedFunctionTable, sizeof(KiUserInvertedFunctionTable))) {
				return false;
			}

			for (ULONG index = 0; index < KiUserInvertedFunctionTable.Count; index++) {
				if (reinterpret_cast<void *>(KiUserInvertedFunctionTable.Entries[index].ImageBase) == MOM_module_get_address(handle)) {
					return true; // Already registered!
				}
			}
		} break;
		case MOM_ARCHITECTURE_AMD32: {
			RTL_INVERTED_FUNCTION_TABLE32 KiUserInvertedFunctionTable;
			if (!MOM_process_read(worker->host(), _LdrpInvertedFunctionTable, &KiUserInvertedFunctionTable, sizeof(KiUserInvertedFunctionTable))) {
				return false;
			}

			for (ULONG index = 0; index < KiUserInvertedFunctionTable.Count; index++) {
				if (POINTER_AS_INT(KiUserInvertedFunctionTable.Entries[index].ImageBase) == POINTER_AS_INT(MOM_module_get_address(handle))) {
					return true;  // Already registered!
				}
			}
		} break;
	}

	BOB_remote_begin64(vworker);
	BOB_remote_push(vworker, (uint64_t)MOM_module_get_address(handle), BOB_NODEREF);
	BOB_remote_push(vworker, (uint64_t)MOM_module_size(handle), BOB_NODEREF);
	BOB_remote_call(vworker, BOB_FASTCALL, _RtlInsertInvertedFunctionTable);
	BOB_remote_save(vworker, 0);
	BOB_remote_notify(vworker);
	BOB_remote_end64(vworker);

	/**
	 * void RtlInsertInvertedFunctionTable(void *ModuleAddress, undefined4 ModuleSize) {
	 *     undefined8 uVar1;
	 *     undefined4 local_res18[2];
	 *     ulonglong local_res20;
	 *     FUN_180013ff4(ModuleAddress,&local_res20,local_res18);
	 *     RtlAcquireSRWLockExclusive(&DAT_18016d500);
	 *     uVar1 = 0;
	 *     FUN_180012224(0);
	 *     FUN_180013f10(uVar1,(ulonglong)ModuleAddress,local_res20,ModuleSize,local_res18[0]);
	 *     FUN_180012224(1);
	 *     RtlReleaseSRWLockExclusive(&DAT_18016d500);
	 *     return;
	 * }
	 */
	BOB_remote_exec(vworker, NULL); // doesn't return anything the function is void!

	switch (worker->arch()) {
		case MOM_ARCHITECTURE_AMD64: {
			RTL_INVERTED_FUNCTION_TABLE64 KiUserInvertedFunctionTable;
			if (!MOM_process_read(worker->host(), _LdrpInvertedFunctionTable, &KiUserInvertedFunctionTable, sizeof(KiUserInvertedFunctionTable))) {
				return false;
			}

			for (ULONG index = 0; index < KiUserInvertedFunctionTable.Count; index++) {
				if (reinterpret_cast<void *>(KiUserInvertedFunctionTable.Entries[index].ImageBase) == MOM_module_get_address(handle)) {
					if (KiUserInvertedFunctionTable.Entries[index].SizeOfTable != 0) {
						return true; // If Image has SAFESEH, RtlInsertInvertedFunctionTable is enough
					}

					// Allocate memory for 2048 possible handlers
					void *memory;
					if (!(memory = MOM_process_allocate(worker->host(), NULL, sizeof(DWORD) * 0x800, MOM_PROTECT_R | MOM_PROTECT_W))) {
						return false;
					}

					uint32_t cookie;
					MOM_process_read(worker->host(), (void *)0x7FFE0330, &cookie, sizeof(cookie));
					uintptr_t encoded = _rotr64(cookie ^ reinterpret_cast<uint64_t>(memory), cookie & 0x3F);

					void *begin = &KiUserInvertedFunctionTable;
					void *field = &KiUserInvertedFunctionTable.Entries[index].ExceptionDirectory;

					void *ptr = POINTER_OFFSET(_LdrpInvertedFunctionTable, (uintptr_t)field - (uintptr_t)begin);

					bool status = true;
					status &= MOM_process_protect(worker->host(), ptr, MOM_module_architecture_pointer_size(worker->arch()), MOM_PROTECT_R | MOM_PROTECT_W);
					status &= (MOM_process_write(worker->host(), ptr, &encoded, MOM_module_architecture_pointer_size(worker->arch())) > 0);
					status &= MOM_process_protect(worker->host(), ptr, MOM_module_architecture_pointer_size(worker->arch()), MOM_PROTECT_R);

					MOM_process_read(worker->host(), _LdrpInvertedFunctionTable, &KiUserInvertedFunctionTable, sizeof(KiUserInvertedFunctionTable));

					if (!status) {
						return false;
					}
				}
			}
		} break;
		case MOM_ARCHITECTURE_AMD32: {
			RTL_INVERTED_FUNCTION_TABLE32 KiUserInvertedFunctionTable;
			if (!MOM_process_read(worker->host(), _LdrpInvertedFunctionTable, &KiUserInvertedFunctionTable, sizeof(KiUserInvertedFunctionTable))) {
				return false;
			}

			for (ULONG index = 0; index < KiUserInvertedFunctionTable.Count; index++) {
				if (POINTER_AS_INT(KiUserInvertedFunctionTable.Entries[index].ImageBase) == POINTER_AS_INT(MOM_module_get_address(handle))) {
					if (KiUserInvertedFunctionTable.Entries[index].SizeOfTable != 0) {
						return true;  // If Image has SAFESEH, RtlInsertInvertedFunctionTable is enough
					}

					// Allocate memory for 2048 possible handlers
					void *memory;
					if (!(memory = MOM_process_allocate(worker->host(), NULL, sizeof(DWORD) * 0x800, MOM_PROTECT_R | MOM_PROTECT_W))) {
						return false;
					}

					uint32_t cookie;
					MOM_process_read(worker->host(), (void *)0x7FFE0330, &cookie, sizeof(cookie));
					uintptr_t encoded = _rotr(cookie ^ POINTER_AS_INT(memory), cookie & 0x1F);

					void *begin = &KiUserInvertedFunctionTable;
					void *field = &KiUserInvertedFunctionTable.Entries[index].ExceptionDirectory;

					void *ptr = POINTER_OFFSET(_LdrpInvertedFunctionTable, (uintptr_t)field - (uintptr_t)begin);

					bool status = true;
					status &= MOM_process_protect(worker->host(), ptr, MOM_module_architecture_pointer_size(worker->arch()), MOM_PROTECT_R | MOM_PROTECT_W);
					status &= (MOM_process_write(worker->host(), ptr, &encoded, MOM_module_architecture_pointer_size(worker->arch())) > 0);
					status &= MOM_process_protect(worker->host(), ptr, MOM_module_architecture_pointer_size(worker->arch()), MOM_PROTECT_R);

					MOM_process_read(worker->host(), _LdrpInvertedFunctionTable, &KiUserInvertedFunctionTable, sizeof(KiUserInvertedFunctionTable));

					if (!status) {
						return false;
					}
				}
			}
		} break;
	}

	// C Exceptions (Requirements)

	ModuleHandle *ntdll = MOM_process_module_find_by_name(worker->host(), "ntdll.dll");
	ModuleExport *rtladdfunctiontable = MOM_module_export_find_by_name(ntdll, "RtlAddFunctionTable");
	void *_RtlAddFunctionTable = MOM_module_export_physical(ntdll, rtladdfunctiontable);

	// C Exceptions

	BOB_remote_begin64(vworker);
	BOB_remote_push(vworker, (uint64_t)MOM_module_get_address(handle), BOB_NODEREF);
	BOB_remote_push(vworker, count, BOB_NODEREF);
	BOB_remote_push(vworker, (uint64_t)seh, BOB_NODEREF);
	BOB_remote_call(vworker, BOB_STDCALL, _RtlAddFunctionTable);
	BOB_remote_save(vworker, 0);
	BOB_remote_notify(vworker);
	BOB_remote_end64(vworker);

	if (!BOB_remote_exec(vworker, NULL)) {
		fprintf(stderr, "[Error] C Exceptions failed.\n");
		return false;
	}

	// Vectored Exception Handler

	void *table;
	if (!(table = MOM_process_allocate(worker->host(), NULL, 0x1000, MOM_PROTECT_R | MOM_PROTECT_W))) {
		return false;
	}
	void *code;
	if (!(code = MOM_process_allocate(worker->host(), NULL, 0x1000, MOM_PROTECT_R | MOM_PROTECT_W | MOM_PROTECT_E))) {
		return false;
	}

	switch (worker->arch()) {
		case MOM_ARCHITECTURE_AMD64: {
			struct MODULE_TABLE64 {
				uint64_t Count;
				struct MODULE_EXCEPTION64 {
					uint64_t Base;
					uint64_t Size;
				} Entries[200];
			};

			MODULE_TABLE64 local;

			// For now this will always be initialized to zero!
			if (!MOM_process_read(worker->host(), table, &local, sizeof(local))) {
				return false;
			}

			local.Entries[local.Count].Base = (uint64_t)MOM_module_get_address(handle);
			local.Entries[local.Count].Size = (uint64_t)MOM_module_size(handle);
			local.Count++;

			if (!MOM_process_write(worker->host(), table, &local, sizeof(local))) {
				return false;
			}
		} break;
		case MOM_ARCHITECTURE_AMD32: {
			struct MODULE_TABLE32 {
				uint32_t Count;
				struct MODULE_EXCEPTION32 {
					uint32_t Base;
					uint32_t Size;
				} Entries[200];
			};

			MODULE_TABLE32 local;

			// For now this will always be initialized to zero!
			if (!MOM_process_read(worker->host(), table, &local, sizeof(local))) {
				return false;
			}

			local.Entries[local.Count].Base = POINTER_AS_INT(MOM_module_get_address(handle));
			local.Entries[local.Count].Size = (uint32_t)MOM_module_size(handle);
			local.Count++;

			if (!MOM_process_write(worker->host(), table, &local, sizeof(local))) {
				return false;
			}
		} break;
	}

	auto replacestub = [](uint8_t *ptr, size_t size, auto oldvalue, auto newvalue) {
		using Tp = std::add_pointer_t<decltype(oldvalue)>;
		for (uint8_t *data = ptr; data < ptr + size - sizeof(oldvalue); data++) {
			if (*reinterpret_cast<Tp>(data) == oldvalue) {
				*reinterpret_cast<Tp>(data) = newvalue;
				return true;
			}
		}
		return false;
	};

	uint8_t cpy[sizeof(VEH32) + sizeof(VEH64)];

	switch (worker->arch()) {
		case MOM_ARCHITECTURE_AMD64: {
			memcpy(cpy, VEH64, sizeof(VEH64));
			replacestub(cpy, sizeof(VEH64), 0xDEADBEEFDEADBEEF, reinterpret_cast<uint64_t>(table));
			replacestub(cpy, sizeof(VEH64), 0xDEADBEEFDEADBEF7, reinterpret_cast<uint64_t>(POINTER_OFFSET(table, sizeof(uint64_t))));

			if (!MOM_process_write(worker->host(), code, cpy, sizeof(VEH64))) {
				return false;
			}
		} break;
		case MOM_ARCHITECTURE_AMD32: {
			memcpy(cpy, VEH32, sizeof(VEH32));

			return false; // TODO!

			if (!MOM_process_write(worker->host(), code, cpy, sizeof(VEH32))) {
				return false;
			}
		} break;
	}

	ModuleExport *rtladdvectoredexceptionhandler = MOM_module_export_find_by_name(ntdll, "RtlAddVectoredExceptionHandler");
	void *_RtlAddVectoredExceptionHandler = MOM_module_export_physical(ntdll, rtladdvectoredexceptionhandler);

	BOB_remote_begin64(vworker);
	BOB_remote_push(vworker, (uint64_t)NULL, BOB_NODEREF);
	BOB_remote_push(vworker, (uint64_t)code, BOB_NODEREF);
	BOB_remote_call(vworker, BOB_STDCALL, _RtlAddVectoredExceptionHandler);
	BOB_remote_save(vworker, 0);
	BOB_remote_notify(vworker);
	BOB_remote_end64(vworker);

	if (BOB_remote_exec(vworker, NULL) == NULL) {
		fprintf(stderr, "[Error] Vectored Exception Handler failed.\n");
		return false;
	}

	// fprintf(stdout, "[Remote] RtlAddVectoredExceptionHandler returned 0x%p\n", (void *)BOB_remote_saved(vworker, 0));

	return true;
}

bool BOB_remote_build_tls(RemoteWorker *vworker, struct ModuleHandle *handle) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	void *_LdrpHandleTlsData = NULL;

	switch (worker->arch()) {
		case MOM_ARCHITECTURE_AMD64: {
			if (!_LdrpHandleTlsData) {
				// fprintf(stdout, "Using Win11 21H2 pattern for LdrpHandleTlsData\n");
				_LdrpHandleTlsData = BOB_remote_ntdll_symbol(vworker, (const unsigned char[]) "\x49\x89\x5b\x10\x49\x89\x73\x18", 8, 0x03);
			}
			if (!_LdrpHandleTlsData) {
				// fprintf(stdout, "Using Win11 21H2 pattern for LdrpHandleTlsData\n");
				_LdrpHandleTlsData = BOB_remote_ntdll_symbol(vworker, (const unsigned char[]) "\x41\x55\x41\x56\x41\x57\x48\x81\xEC\xF0", 10, 0x0f);
			}
			if (!_LdrpHandleTlsData) {
				// fprintf(stdout, "Using Win10 19H1 pattern for LdrpHandleTlsData\n");
				_LdrpHandleTlsData = BOB_remote_ntdll_symbol(vworker, (const unsigned char[]) "\x74\x33\x44\x8d\x43\x09", 6, 0x46);
			}
			if (!_LdrpHandleTlsData) {
				// fprintf(stdout, "Using Win10 10RS4 pattern for LdrpHandleTlsData\n");s
				_LdrpHandleTlsData = BOB_remote_ntdll_symbol(vworker, (const unsigned char[]) "\x74\x33\x44\x8d\x43\x09", 6, 0x44);
			}
			if (!_LdrpHandleTlsData) {
				// fprintf(stdout, "Using Win10 19H1 pattern for LdrpHandleTlsData\n");
				_LdrpHandleTlsData = BOB_remote_ntdll_symbol(vworker, (const unsigned char[]) "\x74\x33\x44\x8d\x43\x09", 6, 0x43);
			}
		} break;
	}

	if (!_LdrpHandleTlsData) {
		/**
		 * Read this shit if this fails! (Google Translate)
		 * https://wiki.chainreactors.red/blog/2025/01/07/IoM_advanced_TLS/#done
		 */
		fprintf(stderr, "[Error] LdrpHandleTlsData not found!\n");
		return false;
	}

	// TODO This is windows architecture dependent!
	LDR_DATA_TABLE_ENTRY self;
	self.DllBase = MOM_module_get_address(handle);

	BOB_remote_begin64(vworker);
	BOB_remote_push_ex(vworker, &self, 0x100);
	BOB_remote_call(vworker, BOB_THISCALL, _LdrpHandleTlsData);
	BOB_remote_save(vworker, 0);
	BOB_remote_notify(vworker);
	BOB_remote_end64(vworker);

	if (!NT_SUCCESS(BOB_remote_exec(vworker, NULL))) {
		// return false;
	}

	return true;
}

void *BOB_remote_load_dep(RemoteWorker *vworker, ModuleHandle *handle) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	WCHAR fullpath[MAX_PATH];
	MultiByteToWideChar(CP_ACP, 0, MOM_module_name(handle), -1, fullpath, MAX_PATH);

	ModuleHandle *ntdll = MOM_process_module_find_by_name(worker->host(), "ntdll.dll");
	ModuleExport *rtlinitunicodestring = MOM_module_export_find_by_name(ntdll, "RtlInitUnicodeString");
	ModuleExport *ldrloaddll = MOM_module_export_find_by_name(ntdll, "LdrLoadDll");
	void *_RtlInitUnicodeString = MOM_module_export_physical(ntdll, rtlinitunicodestring);
	void *_LdrLoadDll = MOM_module_export_physical(ntdll, ldrloaddll);

	BOB_remote_begin64(vworker);

	// RtlInitUnicodeString
	void *UnicodeString = BOB_remote_push_ex(vworker, NULL, 0x20);
	BOB_remote_push_wide(vworker, fullpath);
	BOB_remote_call(vworker, BOB_STDCALL, _RtlInitUnicodeString);

	// LdrLoadDll
	BOB_remote_push(vworker, NULL, BOB_NODEREF);
	BOB_remote_push(vworker, 0, BOB_NODEREF);
	BOB_remote_push(vworker, reinterpret_cast<uint64_t>(UnicodeString), BOB_NODEREF);
	void *Module = BOB_remote_push_ex(vworker, NULL, sizeof(HMODULE));
	BOB_remote_call(vworker, BOB_STDCALL, _LdrLoadDll);
	BOB_remote_save(vworker, 0);
	BOB_remote_notify(vworker);

	BOB_remote_end64(vworker);

	// fprintf(stdout, "[Remote] LdrLoadDll launched\n");

	if (!NT_SUCCESS(BOB_remote_exec(vworker, NULL))) {
		fprintf(stderr, "[Error] LdrLoadDll %s returned error 0x%p\n", MOM_module_name(handle), (void *)BOB_remote_saved(vworker, 0));
		return NULL;
	}

	HMODULE module;
	if (!MOM_process_read(worker->host(), Module, &module, sizeof(module))) {
		return NULL;
	}

	return module;
}

bool BOB_remote_call_entry(RemoteWorker *vworker, struct ModuleHandle *handle) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	if (!MOM_module_entry_physical(handle)) {
		return true;
	}

	BOB_remote_begin64(vworker);
	BOB_remote_bind_manifest(vworker);
	// BOB_remote_breakpoint(vworker);
	
	ListBase entries = MOM_module_tls(handle);
	LISTBASE_FOREACH(ModuleTLS *, tls, &entries) {
		BOB_remote_push(vworker, reinterpret_cast<uint64_t>(MOM_module_get_address(handle)), BOB_NODEREF);
		BOB_remote_push(vworker, 1, BOB_NODEREF); // DLL_PROCESS_ATTACH
		BOB_remote_push(vworker, 0, BOB_NODEREF);
		BOB_remote_call(vworker, BOB_STDCALL, MOM_module_tls_physical(handle, tls));
		// fprintf(stdout, "[Remote] TLS entry 0x%p\n", MOM_module_tls_physical(handle, tls));
	}

	BOB_remote_push(vworker, reinterpret_cast<uint64_t>(MOM_module_get_address(handle)), BOB_NODEREF);
	BOB_remote_push(vworker, 1, BOB_NODEREF); // DLL_PROCESS_ATTACH
	BOB_remote_push(vworker, 0, BOB_NODEREF);
	BOB_remote_call(vworker, BOB_STDCALL, MOM_module_entry_physical(handle));
	BOB_remote_save(vworker, 0);
	BOB_remote_unbind_manifest(vworker);
	BOB_remote_notify(vworker);
	BOB_remote_end64(vworker);

	// fprintf(stdout, "[Remote] DLL entry 0x%p\n", MOM_module_entry_physical(handle));

	if (!BOB_remote_exec(vworker, NULL)) {
		fprintf(stderr, "[Error] Entry failed\n");
		return false;
	}

	// fprintf(stdout, "[Remote] TLS returned %s\n", (NT_SUCCESS(BOB_remote_saved(vworker, 3))) ? "TRUE" : "FALSE");
	// fprintf(stdout, "[Remote] BindManifest returned %s\n", (NT_SUCCESS(BOB_remote_saved(vworker, 1))) ? "TRUE" : "FALSE");
	// fprintf(stdout, "[Remote] Entry 0x%p returned %s\n", MOM_module_entry_physical(handle), (BOB_remote_saved(vworker, 0)) ? "TRUE" : "FALSE");
	// fprintf(stdout, "[Remote] UnbindManifest returned %s\n", (NT_SUCCESS(BOB_remote_saved(vworker, 2))) ? "TRUE" : "FALSE");

	return true;
}

#endif

/** \} */
