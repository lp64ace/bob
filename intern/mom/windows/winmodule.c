#include "MEM_guardedalloc.h"

#include "defines.h"

#include "intern/mom_internal.h"
#include "mom.h"
#include "winmom.h" // Keep last!

#include <pathcch.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

#define DOS(handle) ((IMAGE_DOS_HEADER *)(handle->image))
#define NT32(handle) ((IMAGE_NT_HEADERS32 *)POINTER_OFFSET(handle->image, DOS(handle)->e_lfanew))
#define NT64(handle) ((IMAGE_NT_HEADERS64 *)POINTER_OFFSET(handle->image, DOS(handle)->e_lfanew))

/* -------------------------------------------------------------------- */
/** \name Module Platform Dependent
 * { */

// Returns the memory address of the virtual address within the loaded buffer from disk
static inline void *winmom_module_resolve_virtual_address_to_disk(ModuleHandle *handle, uintptr_t virtual_address) {
	if ((void *)handle->disk == NULL || (void *)virtual_address == NULL) {
		return NULL;
	}

	if (handle->base < virtual_address) {
		virtual_address = virtual_address - handle->base;
	}

	switch (MOM_module_architecture(handle)) {
		case MOM_ARCHITECTURE_AMD32: {
			IMAGE_NT_HEADERS32 *nt = NT32(handle);

			for (IMAGE_SECTION_HEADER *header = IMAGE_FIRST_SECTION(nt); header != IMAGE_FIRST_SECTION(nt) + nt->FileHeader.NumberOfSections; header++) {
				if (header->VirtualAddress <= virtual_address && virtual_address < header->VirtualAddress + header->Misc.VirtualSize) {
					return POINTER_OFFSET((void *)handle->disk, virtual_address - header->VirtualAddress + header->PointerToRawData);
				}
			}

			if (virtual_address < nt->OptionalHeader.SizeOfHeaders) {
				return POINTER_OFFSET(handle->disk, virtual_address);
			}
		} break;
		case MOM_ARCHITECTURE_AMD64: {
			IMAGE_NT_HEADERS64 *nt = NT64(handle);

			for (IMAGE_SECTION_HEADER *header = IMAGE_FIRST_SECTION(nt); header != IMAGE_FIRST_SECTION(nt) + nt->FileHeader.NumberOfSections; header++) {
				if (header->VirtualAddress <= virtual_address && virtual_address < header->VirtualAddress + header->Misc.VirtualSize) {
					return POINTER_OFFSET((void *)handle->disk, virtual_address - header->VirtualAddress + header->PointerToRawData);
				}
			}

			if (virtual_address < nt->OptionalHeader.SizeOfHeaders) {
				return POINTER_OFFSET(handle->disk, virtual_address);
			}
		} break;
	}

	return NULL;
}

// Returns the real address of the virtual address within the already loaded module
static inline void *winmom_module_resolve_virtual_address_to_memory(ModuleHandle *handle, uintptr_t virtual_address) {
	if ((void *)handle->real == NULL || (void *)virtual_address == NULL) {
		return NULL;
	}

	if (handle->base < virtual_address) {
		virtual_address = virtual_address - handle->base;
	}

	switch (MOM_module_architecture(handle)) {
		case MOM_ARCHITECTURE_AMD32: {
			IMAGE_NT_HEADERS32 *nt = NT32(handle);

			return POINTER_OFFSET((void *)handle->real, virtual_address);
		} break;
		case MOM_ARCHITECTURE_AMD64: {
			IMAGE_NT_HEADERS64 *nt = NT64(handle);

			return POINTER_OFFSET((void *)handle->real, virtual_address);
		} break;
	}

	return NULL;
}

// Returns the memory address of the virtual address within the loaded buffer from memory
static inline void *winmom_module_resolve_virtual_address_to_image(ModuleHandle *handle, uintptr_t virtual_address) {
	if (handle->disk) {
		return winmom_module_resolve_virtual_address_to_disk(handle, virtual_address);
	}
	if (handle->real) {
		void *remote = winmom_module_resolve_virtual_address_to_memory(handle, virtual_address);
		if (remote) {
			return POINTER_OFFSET(handle->image, (const uint8_t *)remote - (const uint8_t *)handle->real);
		}
	}
	return NULL;
}

HMODULE winmom_module_handle(ModuleHandle *handle) {
	return (HMODULE)handle->real;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Module Internal
 * { */

/* This cannot assume any data initialization within the #ModuleHandle other than the image itself! */
static bool winmom_module_header_is_valid(const ModuleHandle *handle) {
	if (((const IMAGE_DOS_HEADER *)handle->image)->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}
	const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)handle->image;
	if (((const IMAGE_NT_HEADERS32 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->Signature == IMAGE_NT_SIGNATURE) {
		if (((const IMAGE_NT_HEADERS32 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			return true;
		}
	}
	if (((const IMAGE_NT_HEADERS64 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->Signature == IMAGE_NT_SIGNATURE) {
		if (((const IMAGE_NT_HEADERS64 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			return true;
		}
	}
	return false;
}

/*
 * Image section header is consistent accross architectures!
 */
static IMAGE_SECTION_HEADER *winmom_module_native_section_begin(ModuleHandle *handle) {
	switch (MOM_module_architecture(handle)) {
		case MOM_ARCHITECTURE_AMD32: {
			return IMAGE_FIRST_SECTION(NT32(handle));
		} break;
		case MOM_ARCHITECTURE_AMD64: {
			return IMAGE_FIRST_SECTION(NT64(handle));
		} break;
	}
	return NULL;
}

static IMAGE_SECTION_HEADER *winmom_module_native_section_end(ModuleHandle *handle) {
	switch (MOM_module_architecture(handle)) {
		case MOM_ARCHITECTURE_AMD32: {
			return IMAGE_FIRST_SECTION(NT32(handle)) + NT32(handle)->FileHeader.NumberOfSections;
		} break;
		case MOM_ARCHITECTURE_AMD64: {
			return IMAGE_FIRST_SECTION(NT64(handle)) + NT64(handle)->FileHeader.NumberOfSections;
		} break;
	}
	return NULL;
}

static size_t winmom_module_native_directory_size(ModuleHandle *handle, int directory) {
	switch (MOM_module_architecture(handle)) {
		case MOM_ARCHITECTURE_AMD32: {
			return NT32(handle)->OptionalHeader.DataDirectory[directory].Size;
		} break;
		case MOM_ARCHITECTURE_AMD64: {
			return NT64(handle)->OptionalHeader.DataDirectory[directory].Size;
		} break;
	}
	return 0;
}

static DWORD winmom_module_native_directory_address(ModuleHandle *handle, int directory) {
	switch (MOM_module_architecture(handle)) {
		case MOM_ARCHITECTURE_AMD32: {
			IMAGE_NT_HEADERS32 *nt = NT32(handle);

			if (!nt->OptionalHeader.DataDirectory[directory].Size) {
				return 0;
			}

			return nt->OptionalHeader.DataDirectory[directory].VirtualAddress;
		} break;
		case MOM_ARCHITECTURE_AMD64: {
			IMAGE_NT_HEADERS64 *nt = NT64(handle);

			if (!nt->OptionalHeader.DataDirectory[directory].Size) {
				return 0;
			}

			return nt->OptionalHeader.DataDirectory[directory].VirtualAddress;
		} break;
	}
	return 0;
}

static void *winmom_module_native_directory(ModuleHandle *handle, int directory) {
	return winmom_module_resolve_virtual_address_to_image(handle, winmom_module_native_directory_address(handle, directory));
}

static bool winmom_module_resolve_sections(ModuleHandle *handle) {
	for (IMAGE_SECTION_HEADER *section = winmom_module_native_section_begin(handle); section != winmom_module_native_section_end(handle); section++) {
		ModuleSection *new = MEM_callocN(sizeof(ModuleSection) + sizeof(IMAGE_SECTION_HEADER), "ModuleSection");
		memcpy(new->private, section, sizeof(IMAGE_SECTION_HEADER));
		LIB_addtail(&handle->sections, new);
	}

	return true;
}

static bool winmom_module_resolve_exports(ModuleHandle *handle) {
	IMAGE_EXPORT_DIRECTORY *directory = winmom_module_native_directory(handle, IMAGE_DIRECTORY_ENTRY_EXPORT);

	if (!directory) {
		return true;
	}

	DWORD *functions = winmom_module_resolve_virtual_address_to_image(handle, directory->AddressOfFunctions);
	DWORD *names = winmom_module_resolve_virtual_address_to_image(handle, directory->AddressOfNames);
	WORD *namedordinals = winmom_module_resolve_virtual_address_to_image(handle, directory->AddressOfNameOrdinals);

	ModuleExport **array = MEM_callocN(sizeof(ModuleExport *) * directory->NumberOfFunctions, "temp");

	uintptr_t address = winmom_module_native_directory_address(handle, IMAGE_DIRECTORY_ENTRY_EXPORT);
	for (DWORD index = 0; index < directory->NumberOfFunctions; index++) {
		ModuleExport *new = MEM_callocN(sizeof(ModuleExport), "ModuleExport");

		if (address <= functions[index] && functions[index] <= address + winmom_module_native_directory_size(handle, IMAGE_DIRECTORY_ENTRY_EXPORT)) {
			char forward[MOM_MAX_LIBNAME_LEN + MOM_MAX_EXPNAME_LEN];
			
			strcpy(forward, winmom_module_resolve_virtual_address_to_image(handle, functions[index]));
			forward[ARRAYSIZE(forward) - 1] = '\0';

			if (sscanf(forward, "%[^.].%s", new->libname, new->fwdname) > 0) {
				snprintf(new->libname, MOM_MAX_LIBNAME_LEN, "%s.dll", new->libname);

				if (new->fwdname[0] == '#') {
					new->ordinal = atoi(new->fwdname + 1);
					new->fwdname[0] = '\0';
				}
			}
		} else {
			new->va = functions[index];
		}

		new->ordinal = index;

		array[index] = new;

		LIB_addtail(&handle->exports, new);
	}

	for (DWORD nindex = 0; nindex < directory->NumberOfNames; nindex++) {
		ModuleExport *exp = array[namedordinals[nindex]];

		if (exp) {
			strcpy(exp->expname, winmom_module_resolve_virtual_address_to_image(handle, names[nindex]));
		}
	}

	MEM_SAFE_FREE(array);

	return true;
}

static bool winmom_module_resolve_import(ModuleHandle *handle, ModuleImport *imported, const void *vthunk, const void *vfunk, const char *libname) {
	uintptr_t address = 0;

	switch (MOM_module_architecture(handle)) {
		case MOM_ARCHITECTURE_AMD32: {
			const IMAGE_THUNK_DATA32 *thunk = vthunk;
			const IMAGE_THUNK_DATA32 *funk = vfunk;

			if (IMAGE_SNAP_BY_ORDINAL32(thunk->u1.Ordinal)) {
				imported->expordinal = IMAGE_ORDINAL32(thunk->u1.Ordinal);
			} else {
				address = thunk->u1.AddressOfData;
			}
		} break;
		case MOM_ARCHITECTURE_AMD64: {
			const IMAGE_THUNK_DATA64 *thunk = vthunk;
			const IMAGE_THUNK_DATA64 *funk = vfunk;

			if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
				imported->expordinal = IMAGE_ORDINAL64(thunk->u1.Ordinal);
			} else {
				address = thunk->u1.AddressOfData;
			}
		} break;
	}

	if (address) {
		IMAGE_IMPORT_BY_NAME *image = winmom_module_resolve_virtual_address_to_image(handle, address);
		if (image) {
			strcpy(imported->expname, image->Name);
		}
	}

	strcpy(imported->libname, libname);

	return true;
}

static bool winmom_module_resolve_imports(ModuleHandle *handle) {
	IMAGE_IMPORT_DESCRIPTOR *directory = winmom_module_native_directory(handle, IMAGE_DIRECTORY_ENTRY_IMPORT);

	if (!directory) {
		return true;
	}

	for (IMAGE_IMPORT_DESCRIPTOR *desc = directory; desc && desc->Name != 0; desc++) {
		char libname[MOM_MAX_LIBNAME_LEN];

		strcpy(libname, winmom_module_resolve_virtual_address_to_image(handle, desc->Name));

		void *thunk = NULL;
		void *funk = NULL;

		if (!desc->OriginalFirstThunk) {
			// This is straight up manipulation of the DLL image but it is fine?!
			desc->OriginalFirstThunk = desc->FirstThunk;
		}

		if ((thunk = winmom_module_resolve_virtual_address_to_image(handle, desc->OriginalFirstThunk))) {
			funk = winmom_module_resolve_virtual_address_to_image(handle, desc->FirstThunk);
		}

		/**
		 * Gotta give a huge thumbs up to microsoft here!
		 * The compiler actually doesn't break my ballz for thunk that may be NULL.
		 *
		 * And logically the funk will be NON-NULL if and only if thunk is NON-NULL.
		 */
		if (!funk) {
			continue;
		}

		/**
		 * If this was CXX and we had constexpr this would be
		 * static_assert(sizeof(IMAGE_THUNK_DATA32) == MOM_module_architecture_pointer_size(MOM_ARCHITECTURE_AMD32), ...);
		 * static_assert(sizeof(IMAGE_THUNK_DATA64) == MOM_module_architecture_pointer_size(MOM_ARCHITECTURE_AMD64), ...);
		 */
		// static_assert(sizeof(IMAGE_THUNK_DATA32) == sizeof(int32_t), "Bad thunk iteration");
		// static_assert(sizeof(IMAGE_THUNK_DATA64) == sizeof(int64_t), "Bad thunk iteration");

		uint64_t zero = 0;

		/**
		 * You think this is fucked, and impossible to understand? You shouldn't open the source code!
		 *
		 * TL;DR Thunks are unions that contain ordinal or name offset and data address,
		 * when zero (memcmp(thunk, &zero, MOM_module_architecture_pointer_size(architecture)) == 0) stop!
		 */
		eMomArchitecture architecture = MOM_module_architecture(handle);
		for (uintptr_t expindex = 0; memcmp(thunk, &zero, MOM_module_architecture_pointer_size(architecture)); expindex++) {
			ModuleImport *new = MEM_callocN(sizeof(ModuleImport), "ModuleImport");

			if (!winmom_module_resolve_import(handle, new, thunk, funk, libname)) {
				// ?
			}

			new->thunk_va = desc->OriginalFirstThunk + expindex * MOM_module_architecture_pointer_size(architecture); // VA
			new->funk_va = desc->FirstThunk + expindex * MOM_module_architecture_pointer_size(architecture);          // VA

			LIB_addtail(&handle->imports, new);

			thunk = POINTER_OFFSET(thunk, MOM_module_architecture_pointer_size(architecture));
			funk = POINTER_OFFSET(funk, MOM_module_architecture_pointer_size(architecture));
		}
	}

	return true;
}

static bool winmom_module_resolve_imports_delayed(ModuleHandle *handle) {
	IMAGE_DELAYLOAD_DESCRIPTOR *directory = winmom_module_native_directory(handle, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);

	if (!directory) {
		return true;
	}

	for (IMAGE_DELAYLOAD_DESCRIPTOR *desc = directory; desc && desc->DllNameRVA != 0; desc++) {
		char libname[MOM_MAX_LIBNAME_LEN];

		strcpy(libname, winmom_module_resolve_virtual_address_to_image(handle, desc->DllNameRVA));

		void *thunk = NULL;
		void *funk = NULL;

		if ((thunk = winmom_module_resolve_virtual_address_to_image(handle, desc->ImportNameTableRVA))) {
			funk = winmom_module_resolve_virtual_address_to_image(handle, desc->ImportAddressTableRVA);
		}

		/**
		 * Gotta give a huge thumbs up to microsoft here!
		 * The compiler actually doesn't break my ballz for thunk that may be NULL.
		 *
		 * And logically the funk will be NON-NULL if and only if thunk is NON-NULL.
		 */
		if (!funk) {
			continue;
		}

		/**
		 * If this was CXX and we had constexpr this would be
		 * static_assert(sizeof(IMAGE_THUNK_DATA32) == MOM_module_architecture_pointer_size(MOM_ARCHITECTURE_AMD32), ...);
		 * static_assert(sizeof(IMAGE_THUNK_DATA64) == MOM_module_architecture_pointer_size(MOM_ARCHITECTURE_AMD64), ...);
		 */
		// static_assert(sizeof(IMAGE_THUNK_DATA32) == sizeof(int32_t), "Bad thunk iteration");
		// static_assert(sizeof(IMAGE_THUNK_DATA64) == sizeof(int64_t), "Bad thunk iteration");

		uint64_t zero = 0;

		/**
		 * You think this is fucked, and impossible to understand? You shouldn't open the source code!
		 *
		 * TL;DR Thunks are unions that contain ordinal or name offset and data address,
		 * when zero (memcmp(thunk, &zero, MOM_module_architecture_pointer_size(architecture)) == 0) stop!
		 */
		eMomArchitecture architecture = MOM_module_architecture(handle);
		for (uintptr_t expindex = 0; memcmp(thunk, &zero, MOM_module_architecture_pointer_size(architecture)); expindex++) {
			ModuleImport *new = MEM_callocN(sizeof(ModuleImport), "ModuleImport (Delayed)");

			if (!winmom_module_resolve_import(handle, new, thunk, funk, libname)) {
				// ?
			}

			new->thunk_va = desc->ImportNameTableRVA + expindex * MOM_module_architecture_pointer_size(architecture);   // VA
			new->funk_va = desc->ImportAddressTableRVA + expindex * MOM_module_architecture_pointer_size(architecture); // VA

			LIB_addtail(&handle->imports_delayed, new);

			thunk = POINTER_OFFSET(thunk, MOM_module_architecture_pointer_size(architecture));
			funk = POINTER_OFFSET(funk, MOM_module_architecture_pointer_size(architecture));
		}
	}

	return true;
}

#ifndef IMR_RELTYPE
#	define IMR_RELTYPE(x) ((x >> 12) & 0xF)
#endif

#ifndef IMR_RELOFFSET
#	define IMR_RELOFFSET(x) (x & 0xFFF)
#endif

bool winmom_module_resolve_relocations(ModuleHandle *handle) {
	IMAGE_BASE_RELOCATION *directory = winmom_module_native_directory(handle, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	if (!directory) {
		return true;
	}

	IMAGE_BASE_RELOCATION *itr = directory;
	while (itr < POINTER_OFFSET(directory, winmom_module_native_directory_size(handle, IMAGE_DIRECTORY_ENTRY_BASERELOC))) {
		DWORD va = itr->VirtualAddress;
		DWORD nrelocations = (itr->SizeOfBlock - 8) / sizeof(WORD);
		PWORD data = POINTER_OFFSET(itr, sizeof(IMAGE_BASE_RELOCATION));

		while (nrelocations--) {
			ModuleRelocation *new = MEM_callocN(sizeof(ModuleRelocation), "ModuleRelocation");

			switch (IMR_RELTYPE(*data)) {
				case IMAGE_REL_BASED_HIGH: {
					new->type = MOM_RELOCATION_HIGH;
				} break;
				case IMAGE_REL_BASED_LOW: {
					new->type = MOM_RELOCATION_LOW;
				} break;
				case IMAGE_REL_BASED_HIGHLOW: {
					new->type = MOM_RELOCATION_HIGHLOW;
				} break;
				case IMAGE_REL_BASED_DIR64: {
					new->type = MOM_RELOCATION_DIR64;
				} break;
				case IMAGE_REL_BASED_ABSOLUTE: {
					new->type = MOM_RELOCATION_ABSOLUTE;
				} break;
				case IMAGE_REL_BASED_HIGHADJ: {
					new->type = MOM_RELOCATION_HIGHADJ;
				} break;
			}

			new->va = va + IMR_RELOFFSET(*data);

			LIB_addtail(&handle->relocations, new);

			data++;
		}


		itr = POINTER_OFFSET(itr, itr->SizeOfBlock);
	}

	return true;
}

static bool winmom_module_resolve_exceptions(ModuleHandle *handle) {
	handle->va_exceptions = winmom_module_native_directory_address(handle, IMAGE_DIRECTORY_ENTRY_EXCEPTION);

	return true;
}

static bool winmom_module_resolve_tls(ModuleHandle *handle) {
	if (!winmom_module_native_directory_address(handle, IMAGE_DIRECTORY_ENTRY_TLS)) {
		return true;
	}

	switch (MOM_module_architecture(handle)) {
		case MOM_ARCHITECTURE_AMD32: {
			IMAGE_TLS_DIRECTORY32 *tls = winmom_module_native_directory(handle, IMAGE_DIRECTORY_ENTRY_TLS);

			handle->va_static_tls = tls->StartAddressOfRawData - handle->base;
			handle->va_index_tls = tls->AddressOfIndex - handle->base;

			uint32_t *ptr = winmom_module_resolve_virtual_address_to_image(handle, tls->AddressOfCallBacks - handle->base);
			while (*ptr) {
				ModuleTLS *new = MEM_callocN(sizeof(ModuleTLS), "TLS");
				new->va = (uintptr_t)(*ptr);
				LIB_addtail(&handle->tls, new);

				ptr++;
			}
		} break;
		case MOM_ARCHITECTURE_AMD64: {
			IMAGE_TLS_DIRECTORY64 *tls = winmom_module_native_directory(handle, IMAGE_DIRECTORY_ENTRY_TLS);

			handle->va_static_tls = tls->StartAddressOfRawData - handle->base;
			handle->va_index_tls = tls->AddressOfIndex - handle->base;

			uint64_t *ptr = winmom_module_resolve_virtual_address_to_image(handle, tls->AddressOfCallBacks - handle->base);
			while (*ptr) {
				ModuleTLS *new = MEM_callocN(sizeof(ModuleTLS), "TLS");
				new->va = (uintptr_t)(*ptr);
				LIB_addtail(&handle->tls, new);

				ptr++;
			}
		} break;
	}

	return true;
}

static bool winmom_module_resolve_manifest(ModuleHandle *handle) {
	IMAGE_RESOURCE_DIRECTORY *resource = winmom_module_native_directory(handle, IMAGE_DIRECTORY_ENTRY_RESOURCE);

	if (!resource) {
		return true;
	}

	uintptr_t rootoffset = sizeof(IMAGE_RESOURCE_DIRECTORY);
	IMAGE_RESOURCE_DIRECTORY *root = resource;
	for (size_t i = 0; i < root->NumberOfIdEntries + root->NumberOfNamedEntries; i++) {
		IMAGE_RESOURCE_DIRECTORY_ENTRY *entry = POINTER_OFFSET(resource, rootoffset);

		if (entry->DataIsDirectory == 0 || entry->Id != 0x18) {
			rootoffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
			continue;
		}

		uintptr_t diroffset = entry->OffsetToDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY);
		IMAGE_RESOURCE_DIRECTORY *directory = POINTER_OFFSET(resource, entry->OffsetToDirectory);
		for (size_t j = 0; j < directory->NumberOfIdEntries + directory->NumberOfNamedEntries; j++) {
			IMAGE_RESOURCE_DIRECTORY_ENTRY *item = POINTER_OFFSET(resource, diroffset);

			if (item->DataIsDirectory == 0 || (item->Id != 1 && item->Id != 2 && item->Id != 3)) {
				diroffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
				continue;
			}

			uintptr_t langoffset = item->OffsetToDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY);
			IMAGE_RESOURCE_DIRECTORY_ENTRY *lang = POINTER_OFFSET(resource, langoffset);
			IMAGE_RESOURCE_DATA_ENTRY *data = POINTER_OFFSET(resource, lang->OffsetToData);

			handle->manifest_begin = data->OffsetToData;
			handle->manifest_end = data->OffsetToData + data->Size;
			return true;
		}
	}

	return true;
}

static bool winmom_module_resolve_cookie(ModuleHandle *handle) {
	IMAGE_LOAD_CONFIG_DIRECTORY *directory = winmom_module_native_directory(handle, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
	
	if (!directory) {
		return true;
	}
	
	handle->cookie = directory->SecurityCookie - handle->base;
	
	return true;
}

static bool winmom_module_resolve(ModuleHandle *handle) {
	if (!winmom_module_resolve_sections(handle)) {
		return false;
	}
	if (!winmom_module_resolve_exports(handle)) {
		return false;
	}
	if (!winmom_module_resolve_imports(handle)) {
		return false;
	}
	if (!winmom_module_resolve_imports_delayed(handle)) {
		return false;
	}
	if (!winmom_module_resolve_relocations(handle)) {
		return false;
	}
	if (!winmom_module_resolve_exceptions(handle)) {
		return false;
	}
	if (!winmom_module_resolve_tls(handle)) {
		return false;
	}
	if (!winmom_module_resolve_manifest(handle)) {
		return false;
	}
	if (!winmom_module_resolve_cookie(handle)) {
		return false;
	}
	return true;
}

// Slow?
bool winmom_module_loaded_match_name(const char *asbolute, const char *name) {
	if (!asbolute) {
		return false;
	}

	for (size_t offset = 0; asbolute[offset]; offset++) {
		if (asbolute[offset] == '\\' || asbolute[offset] == '/') {
			if (_stricmp(POINTER_OFFSET(asbolute, offset + 1), name) == 0) {
				return true;
			}
		}
	}

	return _stricmp(asbolute, name) == 0;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Module
 * { */

static ModuleHandle *winmom_module_open_by_file_from_disk(const char *fullpath) {
	ModuleHandle *handle = NULL;

	HANDLE fpin = CreateFile(fullpath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (fpin == INVALID_HANDLE_VALUE) {
		return handle;
	}

	/**
	 * The new DLLs with the long names are anyway just stubs in which all exported 
	 * functions are implemented no more than needed for hard-coded failure. Moreover, 
	 * these failing implementations have not all received great care: see for instance 
	 * that CreateFileW in API-MS-Win-Core-File-L1-1-0.dll returns a hard-coded NULL 
	 * (0) instead of INVALID_HANDLE_VALUE (-1). 
	 * 
	 * https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
	 * 
	 * \note I have never actually seen this happen (didn't try to test it)!
	 */
	if (fpin == NULL) {
		return handle;
	}

	LARGE_INTEGER size;
	if (GetFileSizeEx(fpin, &size)) {
		void *image = MEM_mallocN((size_t)size.QuadPart, "image");

		size_t total = 0;
		while (total < size.QuadPart) {
			DWORD toread = (size.QuadPart - total < 0x1000) ? size.QuadPart - total : 0x1000;
			DWORD inread;
			if (!ReadFile(fpin, POINTER_OFFSET(image, total), toread, &inread, NULL)) {
				break;
			}

			total = total + inread;
		}

		if ((handle = MOM_module_open_by_image(image, total))) {
			strcpy(handle->dllname, fullpath);
		}

		MEM_SAFE_FREE(image);
	}

	CloseHandle(fpin);

	return handle;
}

static ModuleHandle *winmom_module_open_by_name_from_memory(ProcessHandle *handle, const char *resolved) {
	LISTBASE_FOREACH(ModuleHandle *, module, &handle->modules) {
		if (winmom_module_loaded_match_name(MOM_module_name(module), resolved)) {
			if (module->real) {
				ModuleHandle *loaded = MOM_module_open_by_address(handle, (void *)module->real, MOM_module_size(module));
				strcpy(loaded->dllname, MOM_module_name(module));
				return loaded;
			}
		}
	}

	return NULL;
}

ListBase winmom_module_open_by_file(const char *name) {
	ListBase list;
	LIB_listbase_clear(&list);

	ListBase schema = winmom_process_resolve_schema(name);
	LISTBASE_FOREACH(SchemaEntry *, entry, &schema) {
		ListBase collection = winmom_module_open_by_file(entry->physical);

		LISTBASE_FOREACH_MUTABLE(ModuleHandle *, handle, &collection) {
			LIB_addtail(&list, handle);
		}
	}
	LIB_freelistN(&schema);

	if (GetFileAttributes(name) != 0xFFFFFFFF) { // qualified name
		LIB_addtail(&list, winmom_module_open_by_file_from_disk(name));
	}

	if (!LIB_listbase_is_empty(&list)) {
		return list;
	}

	const char *filename = PathFindFileName(name);

	{
		HKEY key;
		if (RegOpenKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", &key) == NO_ERROR) {
			CHAR value[MOM_MAX_DLLNAME_LEN];
			CHAR data[MOM_MAX_DLLNAME_LEN];

			DWORD size = ARRAYSIZE(value), type = 0;
			for (DWORD index = 0; RegEnumValue(key, index, value, &size, NULL, &type, data, &size) == NO_ERROR; index++) {
				size = ARRAYSIZE(value);

				if (strcmp(data, filename) == 0) {
					CHAR system[MOM_MAX_DLLNAME_LEN];
					GetSystemDirectory(system, ARRAYSIZE(system));

					strcpy(value, system);
					strcat(value, "\\");
					strcat(value, data);

					LIB_addtail(&list, winmom_module_open_by_file_from_disk(value));
				}
			}
		}
	}

	if (!LIB_listbase_is_empty(&list)) {
		return list;
	}

	{
		CHAR value[MOM_MAX_DLLNAME_LEN];
		CHAR data[MOM_MAX_DLLNAME_LEN];

		GetCurrentDirectory(ARRAYSIZE(data), data);
		strcpy(value, data);
		strcat(value, "\\");
		strcat(value, filename);

		if (GetFileAttributes(value) != 0xFFFFFFFF) { // qualified name
			LIB_addtail(&list, winmom_module_open_by_file_from_disk(value));
		}
	}

	if (!LIB_listbase_is_empty(&list)) {
		return list;
	}

	{
		CHAR *data = MEM_mallocN(0x1000, "PATH");
		CHAR value[MOM_MAX_DLLNAME_LEN];

		char *ctx = NULL;

		GetEnvironmentVariable("PATH", data, 0x1000);
		for (char *dir = strtok_s(data, ";", &ctx); dir; dir = strtok_s(ctx, L";", &ctx)) {
			strcpy(value, dir);
			strcat(value, "\\");
			strcat(value, filename);

			if (GetFileAttributes(value) != 0xFFFFFFFF) { // qualified name
				LIB_addtail(&list, winmom_module_open_by_file_from_disk(value));
			}
		}

		MEM_freeN(data);
	}

	if (!LIB_listbase_is_empty(&list)) {
		return list;
	}

	return list;
}

ListBase winmom_module_open_by_name(ProcessHandle *process, const char *name) {
	ListBase list;
	LIB_listbase_clear(&list);

	ListBase schema = winmom_process_resolve_schema(name);
	LISTBASE_FOREACH(SchemaEntry *, entry, &schema) {
		ListBase collection = winmom_module_open_by_name(process, entry->physical);

		LISTBASE_FOREACH_MUTABLE(ModuleHandle *, handle, &collection) {
			LIB_addtail(&list, handle);
		}
	}
	
	LIB_addtail(&list, winmom_module_open_by_name_from_memory(process, name));
	LIB_freelistN(&schema);

	return list;
}

ModuleHandle *winmom_module_open_by_image(const void *image, size_t length) {
	ModuleHandle *handle = MEM_callocN(sizeof(ModuleHandle) + length, "ModuleHandle");

	handle->disk = (uintptr_t)handle->image;

	memcpy(handle->image, image, length);

	switch (MOM_module_architecture(handle)) {
		case MOM_ARCHITECTURE_AMD32: {
			handle->base = NT32(handle)->OptionalHeader.ImageBase;
		} break;
		case MOM_ARCHITECTURE_AMD64: {
			handle->base = NT64(handle)->OptionalHeader.ImageBase;
		} break;
	}

	if (!winmom_module_resolve(handle)) {
		MOM_module_close(handle);
		handle = NULL;
	}

	return handle;
}

ModuleHandle *winmom_module_open_by_address(ProcessHandle *process, const void *address, size_t length) {
	ModuleHandle *handle = MEM_callocN(sizeof(ModuleHandle) + length, "ModuleHandle");

	handle->process = process;
	handle->real = (uintptr_t)address;
	handle->base = (uintptr_t)address;

	if (handle->process) {
		MOM_process_read(handle->process, address, handle->image, length);
	} else {
		memcpy(handle->image, address, length);
	}

	if (!winmom_module_resolve(handle)) {
		MOM_module_close(handle);
		handle = NULL;
	}

	return handle;
}

size_t winmom_module_size(ModuleHandle *handle) {
	uintptr_t lo = 0x7FFFFFFFFFFFFFFF;
	uintptr_t hi = 0x0000000000000000;
	for (IMAGE_SECTION_HEADER *section = winmom_module_native_section_begin(handle); section != winmom_module_native_section_end(handle); section++) {
		lo = (lo < section->VirtualAddress) ? lo : section->VirtualAddress;
		hi = (hi > section->VirtualAddress + section->Misc.VirtualSize) ? hi : section->VirtualAddress + section->Misc.VirtualSize;
	}
	// Why not hi - lo? Because this is the memory in the sections! the virtual address starts from the headers (zero)!
	return hi;
}

size_t winmom_module_header_size(ModuleHandle *handle) {
	IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)handle->image;
	if (((IMAGE_NT_HEADERS32 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->Signature == IMAGE_NT_SIGNATURE) {
		if (((IMAGE_NT_HEADERS32 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			return NT32(handle)->OptionalHeader.SizeOfHeaders;
		}
	}
	if (((IMAGE_NT_HEADERS64 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->Signature == IMAGE_NT_SIGNATURE) {
		if (((IMAGE_NT_HEADERS64 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			return NT64(handle)->OptionalHeader.SizeOfHeaders;
		}
	}
	return 0;
}

void winmom_module_close(ModuleHandle *handle) {
	LISTBASE_FOREACH_MUTABLE(ModuleSection *, section, &handle->sections) {
		MEM_freeN(section);
	}
	LISTBASE_FOREACH_MUTABLE(ModuleExport *, exported, &handle->exports) {
		MEM_freeN(exported);
	}
	LISTBASE_FOREACH_MUTABLE(ModuleImport *, imported, &handle->imports) {
		MEM_freeN(imported);
	}
	LISTBASE_FOREACH_MUTABLE(ModuleImport *, imported, &handle->imports_delayed) {
		MEM_freeN(imported);
	}
	LISTBASE_FOREACH_MUTABLE(ModuleRelocation *, relocation, &handle->relocations) {
		MEM_freeN(relocation);
	}
	LISTBASE_FOREACH_MUTABLE(ModuleTLS *, tls, &handle->tls) {
		MEM_freeN(tls);
	}

	MEM_freeN(handle);
}

eMomArchitecture winmom_module_architecture(ModuleHandle *handle) {
	IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)handle->image;
	if (((IMAGE_NT_HEADERS32 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->Signature == IMAGE_NT_SIGNATURE) {
		if (((IMAGE_NT_HEADERS32 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			return MOM_ARCHITECTURE_AMD32;
		}
	}
	if (((IMAGE_NT_HEADERS64 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->Signature == IMAGE_NT_SIGNATURE) {
		if (((IMAGE_NT_HEADERS64 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			return MOM_ARCHITECTURE_AMD64;
		}
	}
	return MOM_ARCHITECTURE_NONE;
}

const char *winmom_module_section_name(ModuleHandle *handle, ModuleSection *section) {
	IMAGE_SECTION_HEADER *header = (IMAGE_SECTION_HEADER *)section->private;

	return header->Name;
}

void *winmom_module_section_logical(ModuleHandle *handle, ModuleSection *section) {
	IMAGE_SECTION_HEADER *header = (IMAGE_SECTION_HEADER *)section->private;

	return winmom_module_resolve_virtual_address_to_image(handle, header->VirtualAddress);
}

void *winmom_module_section_physical(ModuleHandle *handle, ModuleSection *section) {
	IMAGE_SECTION_HEADER *header = (IMAGE_SECTION_HEADER *)section->private;

	return winmom_module_resolve_virtual_address_to_memory(handle, header->VirtualAddress);
}

int winmom_module_section_protection(ModuleHandle *handle, ModuleSection *section) {
	IMAGE_SECTION_HEADER *header = (IMAGE_SECTION_HEADER *)section->private;

	if (header->Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) {
		int protection = 0;
		if ((header->Characteristics & IMAGE_SCN_MEM_READ) != 0) {
			protection |= MOM_PROTECT_R;
		}
		if ((header->Characteristics & IMAGE_SCN_MEM_WRITE) != 0) {
			protection |= MOM_PROTECT_W;
		}
		if ((header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
			protection |= MOM_PROTECT_E;
		}
		return protection;
	}

	return 0;
}

size_t winmom_module_section_raw_size(ModuleHandle *handle, ModuleSection *section) {
	IMAGE_SECTION_HEADER *header = (IMAGE_SECTION_HEADER *)section->private;

	return header->SizeOfRawData;
}

size_t winmom_module_section_size(ModuleHandle *handle, ModuleSection *section) {
	IMAGE_SECTION_HEADER *header = (IMAGE_SECTION_HEADER *)section->private;

	return header->Misc.VirtualSize;
}

void *winmom_module_export_logical(ModuleHandle *handle, ModuleExport *exported) {
	return winmom_module_resolve_virtual_address_to_image(handle, exported->va);
}

void *winmom_module_export_physical(ModuleHandle *handle, ModuleExport *exported) {
	return winmom_module_resolve_virtual_address_to_memory(handle, exported->va);
}

void *winmom_module_import_logical_thunk(ModuleHandle *handle, ModuleImport *exported) {
	return winmom_module_resolve_virtual_address_to_image(handle, exported->thunk_va);
}

void *winmom_module_import_logical_funk(ModuleHandle *handle, ModuleImport *exported) {
	return winmom_module_resolve_virtual_address_to_image(handle, exported->funk_va);
}

void *winmom_module_import_physical_thunk(ModuleHandle *handle, ModuleImport *exported) {
	return winmom_module_resolve_virtual_address_to_memory(handle, exported->thunk_va);
}

void *winmom_module_import_physical_funk(ModuleHandle *handle, ModuleImport *exported) {
	return winmom_module_resolve_virtual_address_to_memory(handle, exported->funk_va);
}

void *winmom_module_relocation_logical(ModuleHandle *handle, ModuleRelocation *exported) {
	return winmom_module_resolve_virtual_address_to_image(handle, exported->va);
}

void *winmom_module_relocation_physical(ModuleHandle *handle, ModuleRelocation *exported) {
	return winmom_module_resolve_virtual_address_to_memory(handle, exported->va);
}

size_t winmom_module_seh_count(ModuleHandle *handle) {
	size_t size = winmom_module_native_directory_size(handle, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
	return size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
}

void *winmom_module_seh_logical(ModuleHandle *handle) {
	return winmom_module_resolve_virtual_address_to_image(handle, handle->va_exceptions);
}

void *winmom_module_seh_physical(ModuleHandle *handle) {
	return winmom_module_resolve_virtual_address_to_memory(handle, handle->va_exceptions);
}

size_t winmom_module_tls_static_size(ModuleHandle *handle) {
	switch (MOM_module_architecture(handle)) {
		case MOM_ARCHITECTURE_AMD32: {
			IMAGE_TLS_DIRECTORY32 *tls = winmom_module_native_directory(handle, IMAGE_DIRECTORY_ENTRY_TLS);

			if (tls) {
				return tls->EndAddressOfRawData - tls->StartAddressOfRawData;
			}
		} break;
		case MOM_ARCHITECTURE_AMD64: {
			IMAGE_TLS_DIRECTORY64 *tls = winmom_module_native_directory(handle, IMAGE_DIRECTORY_ENTRY_TLS);

			if (tls) {
				return tls->EndAddressOfRawData - tls->StartAddressOfRawData;
			}
		} break;
	}
	return 0;
}

void *winmom_module_tls_static_logical(ModuleHandle *handle) {
	return winmom_module_resolve_virtual_address_to_image(handle, handle->va_static_tls);
}

void *winmom_module_tls_static_physical(ModuleHandle *handle) {
	return winmom_module_resolve_virtual_address_to_memory(handle, handle->va_static_tls);
}

void *winmom_module_tls_table_logical(ModuleHandle *handle) {
	uintptr_t va = winmom_module_native_directory_address(handle, IMAGE_DIRECTORY_ENTRY_TLS);

	return winmom_module_resolve_virtual_address_to_image(handle, va);
}

void *winmom_module_tls_table_physical(ModuleHandle *handle) {
	uintptr_t va = winmom_module_native_directory_address(handle, IMAGE_DIRECTORY_ENTRY_TLS);

	return winmom_module_resolve_virtual_address_to_memory(handle, va);
}

int winmom_module_tls_index(ModuleHandle *handle) {
	switch (MOM_module_architecture(handle)) {
		case MOM_ARCHITECTURE_AMD32: {
			int32_t index = *(int32_t *)winmom_module_resolve_virtual_address_to_image(handle, handle->va_index_tls);

			return index;
		} break;
		case MOM_ARCHITECTURE_AMD64: {
			int64_t index = *(int64_t *)winmom_module_resolve_virtual_address_to_image(handle, handle->va_index_tls);

			return index;
		} break;
	}
	return 0;
}

void *winmom_module_tls_logical(ModuleHandle *handle, ModuleTLS *tls) {
	return winmom_module_resolve_virtual_address_to_image(handle, tls->va);
}

void *winmom_module_tls_physical(ModuleHandle *handle, ModuleTLS *tls) {
	return winmom_module_resolve_virtual_address_to_memory(handle, tls->va);
}

size_t winmom_module_manifest_size(ModuleHandle *handle) {
	return handle->manifest_end - handle->manifest_begin;
}

void *winmom_module_manifest_logical(ModuleHandle *handle) {
	return winmom_module_resolve_virtual_address_to_image(handle, handle->manifest_begin);
}

void *winmom_module_manifest_physical(ModuleHandle *handle) {
	return winmom_module_resolve_virtual_address_to_memory(handle, handle->manifest_begin);
}

void *winmom_module_entry_logical(ModuleHandle *handle) {
	switch (MOM_module_architecture(handle)) {
		case MOM_ARCHITECTURE_AMD32: {
			IMAGE_NT_HEADERS32 *nt = NT32(handle);

			return winmom_module_resolve_virtual_address_to_image(handle, nt->OptionalHeader.AddressOfEntryPoint);
		} break;
		case MOM_ARCHITECTURE_AMD64: {
			IMAGE_NT_HEADERS64 *nt = NT64(handle);

			return winmom_module_resolve_virtual_address_to_image(handle, nt->OptionalHeader.AddressOfEntryPoint);
		} break;
	}
	return 0;
}

void *winmom_module_entry_physical(ModuleHandle *handle) {
	switch (MOM_module_architecture(handle)) {
		case MOM_ARCHITECTURE_AMD32: {
			IMAGE_NT_HEADERS32 *nt = NT32(handle);

			return winmom_module_resolve_virtual_address_to_memory(handle, nt->OptionalHeader.AddressOfEntryPoint);
		} break;
		case MOM_ARCHITECTURE_AMD64: {
			IMAGE_NT_HEADERS64 *nt = NT64(handle);

			return winmom_module_resolve_virtual_address_to_memory(handle, nt->OptionalHeader.AddressOfEntryPoint);
		} break;
	}
	return 0;
}

void *winmom_module_cookie_virtual(ModuleHandle *handle) {
	return (void *)handle->cookie;
}

void *winmom_module_cookie_logical(ModuleHandle *handle) {
	return winmom_module_resolve_virtual_address_to_image(handle, handle->cookie);
}

void *winmom_module_cookie_physical(ModuleHandle *handle) {
	return winmom_module_resolve_virtual_address_to_memory(handle, handle->cookie);
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Exports
 * { */

fnMOM_module_open_by_file MOM_module_open_by_file = winmom_module_open_by_file;
fnMOM_module_open_by_name MOM_module_open_by_name = winmom_module_open_by_name;
fnMOM_module_open_by_image MOM_module_open_by_image = winmom_module_open_by_image;
fnMOM_module_open_by_address MOM_module_open_by_address = winmom_module_open_by_address;
fnMOM_module_size MOM_module_size = winmom_module_size;
fnMOM_module_header_size MOM_module_header_size = winmom_module_header_size;

fnMOM_module_close MOM_module_close = winmom_module_close;

fnMOM_module_architecture MOM_module_architecture = winmom_module_architecture;

fnMOM_module_section_name MOM_module_section_name = winmom_module_section_name;
fnMOM_module_section_logical MOM_module_section_logical = winmom_module_section_logical;
// Even if this doesn't return NULL the return address may not be owned by this process!
fnMOM_module_section_physical MOM_module_section_physical = winmom_module_section_physical;
fnMOM_module_section_protection MOM_module_section_protection = winmom_module_section_protection;
fnMOM_module_section_raw_size MOM_module_section_raw_size = winmom_module_section_raw_size;
fnMOM_module_section_size MOM_module_section_size = winmom_module_section_size;

fnMOM_module_export_logical MOM_module_export_logical = winmom_module_export_logical;
fnMOM_module_export_physical MOM_module_export_physical = winmom_module_export_physical;

fnMOM_module_import_logical_thunk MOM_module_import_logical_thunk = winmom_module_import_logical_thunk;
fnMOM_module_import_logical_funk MOM_module_import_logical_funk = winmom_module_import_logical_funk;
fnMOM_module_import_physical_thunk MOM_module_import_physical_thunk = winmom_module_import_physical_thunk;
fnMOM_module_import_physical_funk MOM_module_import_physical_funk = winmom_module_import_physical_funk;

fnMOM_module_relocation_logical MOM_module_relocation_logical = winmom_module_relocation_logical;
fnMOM_module_relocation_physical MOM_module_relocation_physical = winmom_module_relocation_physical;

fnMOM_module_header_is_valid MOM_module_header_is_valid = winmom_module_header_is_valid;

fnMOM_module_seh_count MOM_module_seh_count = winmom_module_seh_count;
fnMOM_module_seh_logical MOM_module_seh_logical = winmom_module_seh_logical;
fnMOM_module_seh_physical MOM_module_seh_physical = winmom_module_seh_physical;

fnMOM_module_tls_static_size MOM_module_tls_static_size = winmom_module_tls_static_size;
fnMOM_module_tls_static_logical MOM_module_tls_static_logical = winmom_module_tls_static_logical;
fnMOM_module_tls_static_physical MOM_module_tls_static_physical = winmom_module_tls_static_physical;
fnMOM_module_tls_table_logical MOM_module_tls_table_logical = winmom_module_tls_table_logical;
fnMOM_module_tls_table_physical MOM_module_tls_table_physical = winmom_module_tls_table_physical;
fnMOM_module_tls_index MOM_module_tls_index = winmom_module_tls_index;
fnMOM_module_tls_logical MOM_module_tls_logical = winmom_module_tls_logical;
fnMOM_module_tls_physical MOM_module_tls_physical = winmom_module_tls_physical;

fnMOM_module_manifest_size MOM_module_manifest_size = winmom_module_manifest_size;
fnMOM_module_manifest_logical MOM_module_manifest_logical = winmom_module_manifest_logical;
fnMOM_module_manifest_physical MOM_module_manifest_physical = winmom_module_manifest_physical;

fnMOM_module_entry_logical MOM_module_entry_logical = winmom_module_entry_logical;
fnMOM_module_entry_physical MOM_module_entry_physical = winmom_module_entry_physical;

fnMOM_module_cookie_virtual MOM_module_cookie_virtual = winmom_module_cookie_virtual;
fnMOM_module_cookie_logical MOM_module_cookie_logical = winmom_module_cookie_logical;
fnMOM_module_cookie_physical MOM_module_cookie_physical = winmom_module_cookie_physical;

/** \} */
