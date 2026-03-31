#include "defines.h"
#include "manualmap.h"
#include "remote.h"

#include "mom.h"

#include <stdio.h>
#include <string.h>

#define LOWORD_UINT32(x) ((uint16_t)((x) & 0xFFFF))
#define HIWORD_UINT32(x) ((uint16_t)(((x) >> 16) & 0xFFFF))

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

void *BOB_manual_map_resolve_import(ProcessHandle *process, const char *libname, const char *expname, int maxhops);

void *BOB_manual_map_resolve_import_ex(ProcessHandle *process, ModuleHandle *existing, const char *libname, const char *expname, int maxhops) {
	ModuleExport *exported = NULL;

	if (((uintptr_t)expname & ~0xFFFF) != 0) {
		exported = MOM_module_export_find_by_name(existing, expname);
	} else {
		exported = MOM_module_export_find_by_ordinal(existing, POINTER_AS_INT(expname));
	}

	if (!exported) {
		return (void *)NULL;
	}

	const char *fwd_libname = MOM_module_export_forward_libname(existing, exported);

	// The export we are looking for exists but it is a forwarded export!
	if (fwd_libname) {
		const char *fwd_expname = MOM_module_export_forward_name(existing, exported);

		if (fwd_expname) {
			return BOB_manual_map_resolve_import(process, fwd_libname, fwd_expname, maxhops - 1);
		} else {
			return BOB_manual_map_resolve_import(process, fwd_libname, POINTER_FROM_INT(MOM_module_export_forward_ordinal(existing, exported)), maxhops - 1);
		}
	}

	if (exported) {
		// The export we are looking for exists and is a normal export!
		return MOM_module_export_physical(existing, exported);
	}

	return NULL;
}

void *BOB_manual_map_resolve_import(ProcessHandle *process, const char *libname, const char *expname, int maxhops) {
	ListBase collection;
	LIB_listbase_clear(&collection);
	
	void *address = NULL;

	ModuleHandle *existing = NULL;
	if ((existing = MOM_process_module_find_by_name(process, libname))) {
		if ((address = BOB_manual_map_resolve_import_ex(process, existing, libname, expname, maxhops - 1))) {
			return address;
		}
	}

	do {
		collection = MOM_module_open_by_name(process, libname);
		if (!LIB_listbase_is_empty(&collection)) {
			break;
		}
		collection = MOM_module_open_by_file(libname);
		if (!LIB_listbase_is_empty(&collection)) {
			break;
		}

		/**
		 * We tried to find the module in an already loaded memory address... we failed!
		 * We tried to find the modile in the disk... we failed!
		 * 
		 * Oh well...!
		 */
		return NULL;
	} while (false);

	LISTBASE_FOREACH(ModuleHandle *, handle, &collection) {

		// We have already loaded this module as a depdency, resolve it!
		if ((existing = MOM_process_module_find(process, handle))) {
			if ((address = BOB_manual_map_resolve_import_ex(process, existing, libname, expname, maxhops - 1))) {
				MOM_module_close_collection(&collection);

				return address;
			}
		}

		// We haven't loaded this module, check if the module contains the export we are looking for!
		ModuleExport *exported = NULL;

		if (((uintptr_t)expname & ~0xFFFF) != 0) {
			exported = MOM_module_export_find_by_name(handle, expname);
		} else {
			exported = MOM_module_export_find_by_ordinal(handle, POINTER_AS_INT(expname));
		}

		if (exported) {
			// Try to manual map the module into the process as well so that we can resolve the export!
			if (BOB_manual_map_module(process, handle, BOB_DEPENDENCY)) {
				MOM_module_close_collection(&collection);

				// The next time we call this #BOB_manual_map_module must have updated the loaded modules to find this one!
				return BOB_manual_map_resolve_import(process, libname, expname, maxhops - 1);
			}
		}
	}

	MOM_module_close_collection(&collection);
	return NULL;
}

bool BOB_manual_map_module_relocation_apply(ProcessHandle *process, ModuleHandle *handle, ModuleRelocation *relocation, ptrdiff_t delta) {
	void *real = MOM_module_get_address(handle);

	switch (MOM_module_relocation_type(handle, relocation)) {
		case MOM_RELOCATION_HIGH: {
			uint16_t value;
			if (!MOM_process_read(process, MOM_module_relocation_physical(handle, relocation), &value, sizeof(value))) {
				return false;
			}

			value += HIWORD_UINT32(delta);

			if (!MOM_process_write(process, MOM_module_relocation_physical(handle, relocation), &value, sizeof(value))) {
				return false;
			}
		} break;
		case MOM_RELOCATION_LOW: {
			uint16_t value;
			if (!MOM_process_read(process, MOM_module_relocation_physical(handle, relocation), &value, sizeof(value))) {
				return false;
			}

			value += LOWORD_UINT32(delta);

			if (!MOM_process_write(process, MOM_module_relocation_physical(handle, relocation), &value, sizeof(value))) {
				return false;
			}
		} break;
		case MOM_RELOCATION_HIGHLOW: {
			uint32_t value;
			if (!MOM_process_read(process, MOM_module_relocation_physical(handle, relocation), &value, sizeof(value))) {
				return false;
			}

			value += delta;

			if (!MOM_process_write(process, MOM_module_relocation_physical(handle, relocation), &value, sizeof(value))) {
				return false;
			}
		} break;
		case MOM_RELOCATION_DIR64: {
			uint64_t value;
			if (!MOM_process_read(process, MOM_module_relocation_physical(handle, relocation), &value, sizeof(value))) {
				return false;
			}

			value += delta;

			if (!MOM_process_write(process, MOM_module_relocation_physical(handle, relocation), &value, sizeof(value))) {
				return false;
			}
		} break;
		case MOM_RELOCATION_ABSOLUTE:
		case MOM_RELOCATION_HIGHADJ: {
			// Nothing to DO!
		} break;
		default: {
			/**
			 * Unimplemented relocation either by BOB or by MOM!
			 */
			return false;
		} break;
	}

	return true;
}

void *BOB_manual_map_module(ProcessHandle *process, ModuleHandle *handle, int flag) {
	ModuleHandle *existing = NULL;
	if ((existing = MOM_process_module_find(process, handle))) {
		return MOM_module_get_address(existing);
	}

	if ((flag & BOB_DEPENDENCY) != 0) {
		RemoteWorker *worker = BOB_remote_worker_open(process, MOM_module_architecture(handle));
		/**
		 * Dependency modules are usually official PE like ucrtbased.dll!
		 * These are 'legit' portable executables but it would be nice to manual map these too!
		 * TODO?
		 */
		// fprintf(stdout, "[BOB] Load %s as dependency!\n", MOM_module_name(handle));

		void *real = NULL;
		if ((real = BOB_remote_load_dep(worker, handle))) {
			MOM_module_set_address(handle, real);
		}

		BOB_remote_worker_close(worker);

		MOM_process_module_push(process, handle);
		return real;
	}

	size_t size = MOM_module_size(handle);

	void *base = ((flag & BOB_REBASE_ALWAYS) == 0) ? (void *)MOM_module_get_base(handle) : NULL;

	void *real = NULL;
	if (!(real = MOM_process_allocate(process, base, size, MOM_PROTECT_R | MOM_PROTECT_W | MOM_PROTECT_E))) {
		// The PE has a base address that likes to be mapped to, but if relocation data are present we can map it elsewhere!
		if (!(real = MOM_process_allocate(process, NULL, size, MOM_PROTECT_R | MOM_PROTECT_W | MOM_PROTECT_E))) {
			return NULL;
		}
	}

	MOM_module_set_address(handle, real);

	// fprintf(stdout, "[BOB] module %s address BEGIN 0x%p END 0x%p\n", MOM_module_name(handle) ? MOM_module_name(handle) : "(null)", real, POINTER_OFFSET(real, size));

	if (!MOM_process_write(process, MOM_module_physical(handle), MOM_module_logical(handle), MOM_module_header_size(handle))) {
		MOM_process_free(process, real);
		return NULL;
	}

	ListBase sections = MOM_module_sections(handle);

	/**
	 * Sections need to be mapped into the memory we allocate in the remote process in order to write the data from file!
	 * \note Protection needs to be updated as well so that some sections are read-only or executable! (Below)
	 */

	LISTBASE_FOREACH(ModuleSection *, section, &sections) {
		if (!MOM_process_write(process, MOM_module_section_physical(handle, section), MOM_module_section_logical(handle, section), MOM_module_section_raw_size(handle, section))) {
			fprintf(stderr, "[BOB] Failed to copy section %s.\n", MOM_module_section_name(handle, section));
			MOM_process_free(process, real);
			return NULL;
		}
	}

	/**
	 * Imports are basically addresses that store pointers to function in other modules.
	 * These needs to be resolved so that the ASM can call them like;
	 * 
	 * \code{.asm}
	 * mov r13 qword ptr [address]
	 * call r13
	 * \endcode
	 * 
	 * The imports especially on windows are a mess, we need to follow imports to different modules, etc...!
	 */

	ListBase imports = MOM_module_imports(handle);
	LISTBASE_FOREACH(ModuleImport *, imported, &imports) {
		void *address = NULL;

		if (MOM_module_import_is_ordinal(handle, imported)) {
			address = BOB_manual_map_resolve_import(process, MOM_module_import_libname(handle, imported), POINTER_FROM_INT(MOM_module_import_expordinal(handle, imported)), 8);
		} else {
			address = BOB_manual_map_resolve_import(process, MOM_module_import_libname(handle, imported), MOM_module_import_expname(handle, imported), 8);
		}

		size_t ptrsize = MOM_module_architecture_pointer_size(MOM_module_architecture(handle));

		/**
		 * There are imports like #QueryOOBESupport from kernel32.dll that on some platforms are non-existing!
		 * These are not reasons to fail the procedure, ignore these imports...
		 */
		if (address) {
			if (!MOM_process_write(process, MOM_module_import_physical_funk(handle, imported), &address, ptrsize)) {
				fprintf(stderr, "[BOB] Failed to copy import to address 0x%p.\n", MOM_module_import_physical_funk(handle, imported));
				MOM_process_free(process, real);
				return NULL;
			}
		}
		else {
			if (MOM_module_import_is_ordinal(handle, imported)) {
				fprintf(stderr, "[BOB] Import %s was not resolved correctly!", MOM_module_import_expname(handle, imported));
			}
			else {
				fprintf(stderr, "[BOB] Import #%hd was not resolved correctly!", MOM_module_import_expordinal(handle, imported));
			}

			/**
			 * I have never seen imports fail to load for a good reason, delay imports on the other hand...
			 */

			MOM_process_free(process, real);
			return NULL;
		}
	}

	ListBase imports_delayed = MOM_module_imports_delayed(handle);
	LISTBASE_FOREACH(ModuleImport *, imported, &imports_delayed) {
		void *address = NULL;

		if (MOM_module_import_is_ordinal(handle, imported)) {
			address = BOB_manual_map_resolve_import(process, MOM_module_import_libname(handle, imported), POINTER_FROM_INT(MOM_module_import_expordinal(handle, imported)), 8);
		} else {
			address = BOB_manual_map_resolve_import(process, MOM_module_import_libname(handle, imported), MOM_module_import_expname(handle, imported), 8);
		}

		size_t ptrsize = MOM_module_architecture_pointer_size(MOM_module_architecture(handle));

		/**
		 * There are imports like #QueryOOBESupport from kernel32.dll that on some platforms are non-existing!
		 * These are not reasons to fail the procedure, ignore these imports...
		 */
		if (address) {
			if (!MOM_process_write(process, MOM_module_import_physical_funk(handle, imported), &address, ptrsize)) {
				fprintf(stderr, "[BOB] Failed to copy import to address 0x%p.\n", MOM_module_import_physical_funk(handle, imported));
				MOM_process_free(process, real);
				return NULL;
			}
		}
		else {
			if (MOM_module_import_is_ordinal(handle, imported)) {
				fprintf(stderr, "[BOB] DELAY Import %s was not resolved correctly!", MOM_module_import_expname(handle, imported));
			}
			else {
				fprintf(stderr, "[BOB] DELAY Import #%hd was not resolved correctly!", MOM_module_import_expordinal(handle, imported));
			}
		}
	}

	/**
	 * Relocations are absolute addresses within the module, these usually reference static variable blocks.
	 * These are the reason we use ? on pattern matching when creating signatures for functions!
	 * 
	 * and relative addressess but that is a different story...!
	 */

	ptrdiff_t delta = (const uint8_t *)MOM_module_get_address(handle) - (const uint8_t *)MOM_module_get_base(handle);

	if (delta != 0) {
		ListBase relocations = MOM_module_relocations(handle);
		LISTBASE_FOREACH(ModuleRelocation *, relocation, &relocations) {
			if (!BOB_manual_map_module_relocation_apply(process, handle, relocation, delta)) {
				fprintf(stderr, "[BOB] Failed to apply relocation.\n");
				MOM_process_free(process, real);
				return NULL;
			}
		}
	}

	// fprintf(stdout, "[BOB] Manifest -----------------------------------------------------------------\n");
	// fprintf(stdout, "%s", (const char *)MOM_module_manifest_logical(handle));
	// fprintf(stdout, "[BOB] Manifest END--------------------------------------------------------------\n");

	/**
	 * Protection needs to be updated as well so that some sections are read-only or executable!
	 */

	LISTBASE_FOREACH(ModuleSection *, section, &sections) {
		int protection = MOM_module_section_protection(handle, section);
		if (!MOM_process_protect(process, MOM_module_section_physical(handle, section), MOM_module_section_size(handle, section), protection)) {
			fprintf(stderr, "[BOB] Failed to protect section %s.\n", MOM_module_section_name(handle, section));
			MOM_process_free(process, real);
			return NULL;
		}
	}

	bool install = true;

	RemoteWorker *worker = BOB_remote_worker_open(process, MOM_module_architecture(handle));

	if (MOM_module_manifest_logical(handle)) {
		if (!BOB_remote_build_manifest(worker, MOM_module_manifest_logical(handle), MOM_module_manifest_size(handle))) {
			install &= false; // When this happens sometimes the remote process crashes!
		}
	}

	if (!BOB_remote_build_seh(worker, handle, MOM_module_seh_physical(handle), MOM_module_seh_count(handle))) {
		install &= false; // When this happens sometimes the remote process crashes!
	}

	if (!BOB_remote_build_cookie(worker, MOM_module_cookie_physical(handle))) {
		install &= false; // When this happens sometimes the remote process crashes!
	}

	if (!BOB_remote_build_tls(worker, handle)) {
		install &= false; // When this happens sometimes the remote process crashes!
	}

	if (!BOB_remote_call_entry(worker, handle)) {
		install &= false; // When this happens sometimes the remote process crashes!
	}

	BOB_remote_worker_close(worker);

	if (!install) {
		MOM_process_free(process, real);
		return NULL;
	}

	MOM_process_module_push(process, handle);
	return MOM_module_get_address(handle);
}

void *BOB_manual_map_image(ProcessHandle *process, const void *image, size_t size, int flag) {
	ModuleHandle *handle = MOM_module_open_by_image(image, size);

	void *real = NULL;
	if ((real = BOB_manual_map_module(process, handle, flag))) {
		// Nothing to do!
	}

	MOM_module_close(handle);
	return real;
}

/** \} */
