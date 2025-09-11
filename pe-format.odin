package pe

IMAGE_DOS_SIGNATURE :: u16le(0x5A4D)
IMAGE_NT_SIGNATURE  :: u32le(0x00004550)

Image_Dos_Header :: struct #align(2) {
   e_magic:    u16le,
   e_cblp:     u16le,
   e_cp:       u16le,
   e_crlc:     u16le,
   e_cparhdr:  u16le,
   e_minalloc: u16le,
   e_maxalloc: u16le,
   e_ss:       u16le,
   e_sp:       u16le,
   e_csum:     u16le,
   e_ip:       u16le,
   e_cs:       u16le,
   e_lfarlc:   u16le,
   e_ovno:     u16le,
   e_res:   [4]u16le,
   e_oemid:    u16le,
   e_oeminfo:  u16le,
   e_res2: [10]u16le,
   e_lfanew:   i32le,
}

is_valid_dos_header :: proc(h: ^Image_Dos_Header, stream_size: int) -> bool {
   LFANEW_PROBE_SIZE :: size_of(u16le)

   if h == nil || stream_size < size_of(Image_Dos_Header) {
      return false
   }

   if h.e_magic != IMAGE_DOS_SIGNATURE || h.e_lfanew < 0 {
      return false
   }

   if h.e_lfanew != 0 {
      if h.e_lfanew < size_of(Image_Dos_Header) {
         return false
      }

      if cast(int) h.e_lfanew > stream_size - LFANEW_PROBE_SIZE {
         return false
      }
   }

   return true
}

Image_File_Machine :: enum u16le {
   UNKNOWN    = 0x0000,
   TARGETHOST = 0x0001,
   I386       = 0x014c,
   R3000      = 0x0162,
   R4000      = 0x0166,
   R10000     = 0x0168,
   WCEMIPSV2  = 0x0169,
   ALPHA      = 0x0184,
   SH3        = 0x01a2,
   SH3DSP     = 0x01a3,
   SH3E       = 0x01a4,
   SH4        = 0x01a6,
   SH5        = 0x01a8,
   ARM        = 0x01c0,
   THUMB      = 0x01c2,
   ARMNT      = 0x01c4,
   AM33       = 0x01d3,
   POWERPC    = 0x01f0,
   POWERPCFP  = 0x01f1,
   IA64       = 0x0200,
   MIPS16     = 0x0266,
   ALPHA64    = 0x0284,
   MIPSFPU    = 0x0366,
   MIPSFPU16  = 0x0466,
   AXP64      = 0x0284,
   TRICORE    = 0x0520,
   CEF        = 0x0CEF,
   EBC        = 0x0EBC,
   AMD64      = 0x8664,
   M32R       = 0x9041,
   ARM64      = 0xAA64,
   CEE        = 0xC0EE,
}

Image_File_Characteristic :: enum u16le {
   RELOCS_STRIPPED         = 0,
   EXECUTABLE_IMAGE        = 1,
   LINE_NUMS_STRIPPED      = 2,
   LOCAL_SYMS_STRIPPED     = 3,
   AGGRESIVE_WS_TRIM       = 4,
   LARGE_ADDRESS_AWARE     = 5,
   BYTES_REVERSED_LO       = 7,
   MACHINE_32BIT           = 8,
   DEBUG_STRIPPED          = 9,
   REMOVABLE_RUN_FROM_SWAP = 10,
   NET_RUN_FROM_SWAP       = 11,
   SYSTEM                  = 12,
   DLL                     = 13,
   UP_SYSTEM_ONLY          = 14,
   BYTES_REVERSED_HI       = 15,
}

Image_File_Characteristics :: distinct bit_set[Image_File_Characteristic; u16le]

Image_File_Header :: struct #align(4) {
   machine:                 Image_File_Machine,
   number_of_sections:      u16le,
   time_date_stamp:         u32le,
   pointer_to_symbol_table: u32le,
   number_of_symbols:       u32le,
   size_of_optional_header: u16le,
   characteristics:         Image_File_Characteristics,
}

Image_Data_Directories :: enum {
   EXPORT         = 0,
   IMPORT         = 1,
   RESOURCE       = 2,
   EXCEPTION      = 3,
   SECURITY       = 4,
   BASERELOC      = 5,
   DEBUG          = 6,
   ARCHITECTURE   = 7,
   GLOBALPTR      = 8,
   TLS            = 9,
   LOAD_CONFIG    = 10,
   BOUND_IMPORT   = 11,
   IAT            = 12,
   DELAY_IMPORT   = 13,
   COM_DESCRIPTOR = 14,
   RESERVED       = 15,
}

Image_Data_Directory :: struct #align(4) {
   virtual_address: u32le,
   size:            u32le,
}

Image_Section_Characteristics :: distinct u32le

IMAGE_SECTION_ALIGN_MASK :: Image_Section_Characteristics(0x00F00000)

Image_Section_Flag :: enum {
   CONTAINS_CODE                =  5,
   CONTAINS_INITIALIZED_DATA    =  6,
   CONTAINS_UNINITIALIZED_DATA  =  7,
   LINK_INFO                    =  9,
   LINK_REMOVE                  =  11,
   LINK_COMDAT                  =  12,
   NO_DEFER_SPEC_EXC            =  14,
   GPREL                        =  15,
   MEM_PURGEABLE                =  17,
   MEM_LOCKED                   =  18,
   MEM_PRELOAD                  =  19,
   LINK_NRELOC_OVFL             =  24,
   MEM_DISCARDABLE              =  25,
   MEM_NOT_CACHED               =  26,
   MEM_NOT_PAGED                =  27,
   MEM_SHARED                   =  28,
   MEM_EXECUTE                  =  29,
   MEM_READ                     =  30,
   MEM_WRITE                    =  31,
}

extract_section_alignment :: proc "contextless" (characteristics: Image_Section_Characteristics) -> int {
   align_bits := characteristics & IMAGE_SECTION_ALIGN_MASK

   if align_bits != 0 {
      return 1 << ((align_bits >> 20) - 1)
   }

   return 16
}

// Flags are the characteristics without the alignment bits.
Image_Section_Flags :: distinct bit_set[Image_Section_Flag; Image_Section_Characteristics]

extract_section_flags :: proc "contextless" (characteristics: Image_Section_Characteristics) -> Image_Section_Flags {
   return transmute(Image_Section_Flags) (characteristics & ~IMAGE_SECTION_ALIGN_MASK)
}

Image_Section_Header :: struct #align(4) {
   name:                   [8]u8,
   virtual_size:           u32le,
   virtual_address:        u32le,
   size_of_raw_data:       u32le,
   pointer_to_raw_data:    u32le,
   pointer_to_relocations: u32le,
   pointer_to_linenumbers: u32le,
   number_of_relocations:  u16le,
   number_of_linenumbers:  u16le,
   characteristics:        Image_Section_Characteristics,
}

Image_Subsystem :: enum u16le {
   UNKNOWN                  = 0,
   NATIVE                   = 1,
   WINDOWS_GUI              = 2,
   WINDOWS_CUI              = 3,
   OS2_CUI                  = 5,
   POSIX_CUI                = 7,
   NATIVE_WINDOWS           = 8,
   WINDOWS_CE_GUI           = 9,
   EFI_APPLICATION          = 10,
   EFI_BOOT_SERVICE_DRIVER  = 11,
   EFI_RUNTIME_DRIVER       = 12,
   EFI_ROM                  = 13,
   XBOX                     = 14,
   WINDOWS_BOOT_APPLICATION = 16,
}

Image_DLL_Characteristic :: enum {
   HighEntropyVa	      = 5,
   DynamicBase	         = 6,
   ForceIntegrity	      = 7,
   NxCompat	            = 8,
   NoIsolation	         = 9,
   NoSeh	               = 10,
   NoBind	            = 11,
   Appcontainer	      = 12,
   WdmDriver	         = 13,
   GuardCf	            = 14,
   TerminalServerAware	= 15,
}

Image_DLL_Characteristics :: distinct bit_set[Image_DLL_Characteristic; u16le]

IMAGE_OPTIONAL_HEADER_MAGIC_PE32 :: u16le(0x10B)
IMAGE_OPTIONAL_HEADER_MAGIC_PE64 :: u16le(0x20B)

Image_Optional_Header32 :: struct #align(4) {
   magic:                          u16le,
   major_linker_version:           u8,
   minor_linker_version:           u8,
   size_of_code:                   u32le,
   size_of_initialized_data:       u32le,
   size_of_uninitialized_data:     u32le,
   address_of_entry_point:         u32le,
   base_of_code:                   u32le,
   base_of_data:                   u32le,
   image_base:                     u32le,
   section_alignment:              u32le,
   file_alignment:                 u32le,
   major_operating_system_version: u16le,
   minor_operating_system_version: u16le,
   major_image_version:            u16le,
   minor_image_version:            u16le,
   major_subsystem_version:        u16le,
   minor_subsystem_version:        u16le,
   win32_version_value:            u32le,
   size_of_image:                  u32le,
   size_of_headers:                u32le,
   check_sum:                      u32le,
   subsystem:                      Image_Subsystem,
   dll_characteristics:            Image_DLL_Characteristics,
   size_of_stack_reserve:          u32le,
   size_of_stack_commit:           u32le,
   size_of_heap_reserve:           u32le,
   size_of_heap_commit:            u32le,
   loader_flags:                   u32le,
   number_of_rva_and_sizes:        u32le,
   data_directory:                 [Image_Data_Directories]Image_Data_Directory,
}

Image_Optional_Header64 :: struct #align(4) {
   magic:                          u16le,
   major_linker_version:           u8,
   minor_linker_version:           u8,
   size_of_code:                   u32le,
   size_of_initialized_data:       u32le,
   size_of_uninitialized_data:     u32le,
   address_of_entry_point:         u32le,
   base_of_code:                   u32le,
   image_base:                     u64le,
   section_alignment:              u32le,
   file_alignment:                 u32le,
   major_operating_system_version: u16le,
   minor_operating_system_version: u16le,
   major_image_version:            u16le,
   minor_image_version:            u16le,
   major_subsystem_version:        u16le,
   minor_subsystem_version:        u16le,
   win32_version_value:            u32le,
   size_of_image:                  u32le,
   size_of_headers:                u32le,
   check_sum:                      u32le,
   subsystem:                      Image_Subsystem,
   dll_characteristics:            Image_DLL_Characteristics,
   size_of_stack_reserve:          u64le,
   size_of_stack_commit:           u64le,
   size_of_heap_reserve:           u64le,
   size_of_heap_commit:            u64le,
   loader_flags:                   u32le,
   number_of_rva_and_sizes:        u32le,
   data_directory:                 [Image_Data_Directories]Image_Data_Directory,
}

size_of_directories :: proc "contextless" (header: ^$T) -> int {
   return cast(int) header.number_of_rva_and_sizes * size_of(Image_Data_Directory)
}

expected_optional_header_size :: proc "contextless" (header: ^$T) -> int {
   return size_of(T) - size_of(header.data_directory) + size_of_directories(header)
}

base_optional_header_size :: proc "contextless" ($T: typeid) -> int {
   return size_of(T) - size_of(T{}.data_directory)
}

validate_optional_header32 :: proc(h: ^Image_Optional_Header32, size_of_optional_header: int) -> bool {
   if h.magic != IMAGE_OPTIONAL_HEADER_MAGIC_PE32 {
      return false
   }

   if cast(int) h.number_of_rva_and_sizes > len(Image_Data_Directories) {
      return false
   }

   return expected_optional_header_size(h) == size_of_optional_header
}

validate_optional_header64 :: proc(h: ^Image_Optional_Header64, size_of_optional_header: int) -> bool {
   if h.magic != IMAGE_OPTIONAL_HEADER_MAGIC_PE64 {
      return false
   }

   if cast(int) h.number_of_rva_and_sizes > len(Image_Data_Directories) {
      return false
   }

   return expected_optional_header_size(h) == size_of_optional_header
}

validate_optional_header :: proc{
   validate_optional_header32,
   validate_optional_header64,
}

Image_Export_Directory :: struct #align(4) {
   characteristics:              u32le,
   time_date_stamp:              u32le,
   major_version:                u16le,
   minor_version:                u16le,
   name:                         u32le,
   base:                         u32le,
   number_of_functions:          u32le,
   number_of_names:              u32le,
   address_of_functions_rva:     u32le,
   address_of_names_rva:         u32le,
   address_of_name_ordinals_rva: u32le,
}

Image_Import_By_Name :: struct #align(4) {
   hint: u16le,
   name: [0]u8,
}

Image_Thunk_Data64 :: struct #raw_union #align(8) {
   forwarder_string: u64le,
   function:         u64le,
   ordinal:          u64le,
   address_of_data:  u64le,
}

Image_Thunk_Data32 :: struct #raw_union #align(4) {
   forwarder_string: u32le,
   function:         u32le,
   ordinal:          u32le,
   address_of_data:  u32le,
}

IMAGE_ORDINAL_FLAG64 :: u64le(0x8000000000000000)
IMAGE_ORDINAL_FLAG32 :: u32le(0x80000000)

image_snap_by_ordinal32 :: proc "contextless" (ordinal: u32le) -> bool {
   return (ordinal & IMAGE_ORDINAL_FLAG32) != 0
}

image_snap_by_ordinal64 :: proc "contextless" (ordinal: u64le) -> bool {
   return (ordinal & IMAGE_ORDINAL_FLAG64) != 0
}

Image_Import_Descriptor :: struct #align(4) {
   u0: struct #raw_union {
      characteristics:      u32le,
      original_first_thunk: u32le,
   },
   time_date_stamp: u32le,
   forwarder_chain: u32le,
   name:            u32le,
   first_thunk:     u32le,
}

Image_Resource_Directory :: struct #align(4) {
   characteristics:         u32le,
   time_date_stamp:         u32le,
   major_version:           u16le,
   minor_version:           u16le,
   number_of_named_entries: u16le,
   number_of_id_entries:    u16le,
}

IMAGE_RESOURCE_NAME_IS_STRING    :: u32le(0x80000000)
IMAGE_RESOURCE_DATA_IS_DIRECTORY :: u32le(0x80000000)

Image_Resource_Directory_Entry :: struct #align(4) {
   u0: struct #raw_union {
      s1: bit_field u32le {
         name_offset:    u32le | 31,
         name_is_string: bool  | 1,
      },
      name: u32le,
      id:   u16le,
   },
   u1: struct #raw_union {
      s2: bit_field u32le {
         offset_to_directory: u32le | 31,
         data_is_directory:   bool  | 1,
      },
      offset_to_data: u32le,
   },
}

Image_Resource_Data_Entry :: struct #align(4) {
   offset_to_data: u32le,
   size:           u32le,
   code_page:      u32le,
   reserved:       u32le,
}

Image_Base_Relocation :: struct #align(4) {
   virtual_address: u32le,
   size_of_block:   u32le,
}

Image_Based_Relocation_Type :: enum u16le {
   ABSOLUTE       = 0,
   HIGH           = 1,
   LOW            = 2,
   HIGHLOW        = 3,
   HIGHADJ        = 4,
   MIPS_JMPADDR   = 5,
   MIPS_JMPADDR16 = 9,
   IA64_IMM64     = 9,
   DIR64          = 10,
}

Image_Tls_Directory64 :: struct #align(4) {
   start_address_of_raw_data: u64le,
   end_address_of_raw_data:   u64le,
   address_of_index:          u64le,
   address_of_call_backs:     u64le,
   size_of_zero_fill:         u32le,
   characteristics:           u32le,
}

Image_Tls_Directory32 :: struct #align(4) {
   start_address_of_raw_data: u32le,
   end_address_of_raw_data:   u32le,
   address_of_index:          u32le,
   address_of_call_backs:     u32le,
   size_of_zero_fill:         u32le,
   characteristics:           u32le,
}

Image_Debug_Type :: enum u32le {
   UNKNOWN       = 0,
   COFF          = 1,
   CODEVIEW      = 2,
   FPO           = 3,
   MISC          = 4,
   EXCEPTION     = 5,
   FIXUP         = 6,
   OMAP_TO_SRC   = 7,
   OMAP_FROM_SRC = 8,
   BORLAND       = 9,
   RESERVED10    = 10,
}

Image_Debug_Directory :: struct #align(4) {
   characteristics: u32le,
   time_date_stamp: u32le,
   major_version:   u16le,
   minor_version:   u16le,
   type:            Image_Debug_Type,
   size_of_data:    u32le,
   address_of_raw_data: u32le,
   pointer_to_raw_data: u32le,
}

Image_Storage_Class :: enum u8 {
   END_OF_FUNCTION     = 0xFF,
   NULL                = 0,
   AUTOMATIC           = 1,
   EXTERNAL            = 2,
   STATIC              = 3,
   REGISTER            = 4,
   EXTERNAL_DEF        = 5,
   LABEL               = 6,
   UNDEFINED_LABEL     = 7,
   MEMBER_OF_STRUCT    = 8,
   ARGUMENT            = 9,
   STRUCT_TAG          = 10,
   MEMBER_OF_UNION     = 11,
   UNION_TAG           = 12,
   TYPE_DEFINITION     = 13,
   UNDEFINED_STATIC    = 14,
   ENUM_TAG            = 15,
   MEMBER_OF_ENUM      = 16,
   REGISTER_PARAM      = 17,
   BIT_FIELD           = 18,
   BLOCK               = 100,
   FUNCTION            = 101,
   END_OF_STRUCT       = 102,
   FILE                = 103,
   SECTION             = 104,
   WEAK_EXTERNAL       = 105,
   CLR_TOKEN           = 107,
}

Image_Symbol :: struct #align(4) {
   u0: struct #raw_union {
      name: struct {
         short: u32le,
         long: u32le,
      },
      short_name: [8]u8,
      long_name:  [2]u32le,
   },
   value:                 u32le,
   section_number:        i16le,
   type:                  u16le,
   storage_class:         Image_Storage_Class,
   number_of_aux_symbols: u8,
}

Runtime_Function :: struct #align(4) {
   begin_address: u32le,
   end_address:   u32le,
   u0: struct #raw_union {
      unwind_info_address: u32le,
      unwind_data:         u32le,
   },
}

Unwind_Opcode :: enum u8 {
   PUSH_NONVOL      = 0,
   ALLOC_LARGE      = 1,
   ALLOC_SMALL      = 2,
   SET_FPREG        = 3,
   SAVE_NONVOL      = 4,
   SAVE_NONVOL_FAR  = 5,
   SAVE_XMM128      = 6,
   SAVE_XMM128_FAR  = 7,
   PUSH_MACHFRAME   = 8,
}

Unwind_Code :: struct #raw_union #align(4) {
   s0: struct {
      code_offset: u8,
      using _: bit_field u8 {
         unwind_op:   u8 | 4,
         op_info:     u8 | 4,
      },
   },
   frame_offset: u16le,
}

Unwind_Info :: struct #align(4) {
   s0: bit_field u8 {
      version:    u8 | 3,
      flags:      u8 | 5,
   },
   size_of_prolog: u8,
   count_of_codes: u8,
   s1: bit_field u8 {
      frame_register: u8 | 4,
      frame_offset:   u8 | 4,
   },
   unwind_code: [1]Unwind_Code,
}

UNW_FLAG_NHANDLER  :: 0
UNW_FLAG_EHANDLER  :: 1
UNW_FLAG_UHANDLER  :: 2
UNW_FLAG_CHAININFO :: 4

Image_Delay_Import_Descriptor :: struct #align(4) {
   attrs:      u32le,
   dll_name:   u32le,
   hmod:       u32le,
   iat:        u32le,
   int:        u32le,
   bound_iat:  u32le,
   unload_iat: u32le,
   time_stamp: u32le,
}

Image_Load_Config_Code_Integrity :: struct #align(4) {
   flags:          u16le,
   catalog:        u16le,
   catalog_offset: u32le,
   reserved:       u32le,
}

Image_Load_Config_Directory_Ex32 :: struct #align(4) {
   size:                                      u32le,
   time_date_stamp:                           u32le,
   major_version:                             u16le,
   minor_version:                             u16le,
   global_flags_clear:                        u32le,
   global_flags_set:                          u32le,
   critical_section_default_timeout:          u32le,
   de_commit_free_block_threshold:            u32le,
   de_commit_total_free_threshold:            u32le,
   lock_prefix_table:                         u32le,
   maximum_allocation_size:                   u32le,
   virtual_memory_threshold:                  u32le,
   process_heap_flags:                        u32le,
   process_affinity_mask:                     u32le,
   csd_version:                               u16le,
   dependent_load_flags:                      u16le,
   edit_list:                                 u32le,
   security_cookie:                           u32le,
   se_handler_table:                          u32le,
   se_handler_count:                          u32le,
   guard_cf_check_function_pointer:           u32le,
   guard_cf_dispatch_function_pointer:        u32le,
   guard_cf_function_table:                   u32le,
   guard_cf_function_count:                   u32le,
   guard_flags:                               u32le,
   code_integrity:                            Image_Load_Config_Code_Integrity,
   guard_address_taken_iat_entry_table:       u32le,
   guard_address_taken_iat_entry_count:       u32le,
   guard_long_jump_target_table:              u32le,
   guard_long_jump_target_count:              u32le,
   dynamic_value_reloc_table:                 u32le,
   chpe_metadata_pointer:                     u32le,
   guard_rf_failure_routine:                  u32le,
   guard_rf_failure_routine_function_pointer: u32le,
   dynamic_value_reloc_table_offset:          u32le,
   dynamic_value_reloc_table_section:         u16le,
   reserved2:                                 u16le,
}

Image_Load_Config_Directory_Ex64 :: struct #align(4) {
	size:                                      u32le,
	time_date_stamp:                           u32le,
	major_version:                             u16le,
	minor_version:                             u16le,
	global_flags_clear:                        u32le,
	global_flags_set:                          u32le,
	critical_section_default_timeout:          u32le,
	de_commit_free_block_threshold:            u64le,
	de_commit_total_free_threshold:            u64le,
	lock_prefix_table:                         u64le,
	maximum_allocation_size:                   u64le,
	virtual_memory_threshold:                  u64le,
	process_affinity_mask:                     u64le,
	process_heap_flags:                        u32le,
	csd_version:                               u16le,
	dependent_load_flags:                      u16le,
	edit_list:                                 u64le,
	security_cookie:                           u64le,
	se_handler_table:                          u64le,
	se_handler_count:                          u64le,
	guard_cf_check_function_pointer:           u64le,
	guard_cf_dispatch_function_pointer:        u64le,
	guard_cf_function_table:                   u64le,
	guard_cf_function_count:                   u64le,
	guard_flags:                               u32le,
	code_integrity:                            Image_Load_Config_Code_Integrity,
	guard_address_taken_iat_entry_table:       u64le,
	guard_address_taken_iat_entry_count:       u64le,
	guard_long_jump_target_table:              u64le,
	guard_long_jump_target_count:              u64le,
	dynamic_value_reloc_table:                 u64le,
	chpe_metadata_pointer:                     u64le,
	guard_rf_failure_routine:                  u64le,
	guard_rf_failure_routine_function_pointer: u64le,
	dynamic_value_reloc_table_offset:          u32le,
	dynamic_value_reloc_table_section:         u16le,
	reserved2:                                 u16le,
}

// @TODO(Sonny): Wrap these all like I have done with the section characteristics.

IMAGE_GUARD_CF_INSTRUMENTED                    :: u32le(0x00000100)
IMAGE_GUARD_CFW_INSTRUMENTED                   :: u32le(0x00000200)
IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT          :: u32le(0x00000400)
IMAGE_GUARD_SECURITY_COOKIE_UNUSED             :: u32le(0x00000800)
IMAGE_GUARD_PROTECT_DELAYLOAD_IAT              :: u32le(0x00001000)
IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION   :: u32le(0x00002000)
IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT :: u32le(0x00004000)
IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION       :: u32le(0x00008000)
IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT          :: u32le(0x00010000)
IMAGE_GUARD_RF_INSTRUMENTED                    :: u32le(0x00020000)
IMAGE_GUARD_RF_ENABLE                          :: u32le(0x00040000)
IMAGE_GUARD_RF_STRICT                          :: u32le(0x00080000)
IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK        :: u32le(0xF0000000)
IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT       :: u32le(28)
