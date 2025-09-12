package pe

IMAGE_NT_SIGNATURE :: u32le(0x00004550)

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

read_file_header :: proc(img: ^Decoded_Image, r: ^Binary_Reader) -> bool {
   file_header: Image_File_Header
   if !reader_read_n(r, &file_header, size_of(file_header)) {
      return false
   }

   validate_machine := proc(h: ^Image_File_Header) -> (result: bool) {
      for m in Image_File_Machine {
         result |= m == h.machine
      }
      return
   }

   if !validate_machine(&file_header) {
      return false
   }

   optional_size  := cast(int) file_header.size_of_optional_header
   if r.i + optional_size > len(r.s) {
      return false
   }

   // COFF symbol table pointers (image files generally have these zeroed; OBJs may not).
   // If present, ensure `pointer_to_symbol_table` is within the file (coarse check).
   if file_header.pointer_to_symbol_table != 0 {
      symbol_table_offset := cast(int) file_header.pointer_to_symbol_table

      if symbol_table_offset >= len(r.s) {
         return false
      }

      symbol_count := cast(int) file_header.number_of_symbols

      if symbol_table_offset + symbol_count * size_of(Image_Symbol) >= len(r.s) {
         return false
      }
   }

   img.file_header = file_header

   return true
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
IMAGE_OPTIONAL_HEADER_MAGIC_ROM  :: u16le(0x107)

Image_CPR_Mask:: distinct [4]u32le

Image_ROM_Optional_Header :: struct #align(4) {
   magic:                        u16le,
   major_linker_version:         u8,
   minor_linker_version:         u8,
   size_of_code:                 u32le,
   size_of_initialized_data:     u32le,
   size_of_uninitialized_data:   u32le,
   address_of_entry_point:       u32le,
   base_of_code:                 u32le,
   base_of_data:                 u32le,
   base_of_bss:                  u32le,
   gpr_mask:                     u32le,
   cpr_mask:                     Image_CPR_Mask,
   gp_value:                     u32le,
}

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

Wrapped_Optional_Header :: struct {
   magic:                          u16le,
   major_linker_version:           u8,
   minor_linker_version:           u8,
   size_of_code:                   u32le,
   size_of_initialized_data:       u32le,
   size_of_uninitialized_data:     u32le,
   address_of_entry_point:         u32le,
   base_of_code:                   u32le,
   base_of_data:                   u32le,
   base_of_bss:                    u32le,
   gpr_mask:                       u32le,
   gp_value:                       u32le,
   cpr_mask:                       Image_CPR_Mask,
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

_wrap_from_rom :: proc(src: ^Image_ROM_Optional_Header) -> (w: Wrapped_Optional_Header) {
   w.magic                          = src.magic
   w.major_linker_version           = src.major_linker_version
   w.minor_linker_version           = src.minor_linker_version
   w.size_of_code                   = src.size_of_code
   w.size_of_initialized_data       = src.size_of_initialized_data
   w.size_of_uninitialized_data     = src.size_of_uninitialized_data
   w.address_of_entry_point         = src.address_of_entry_point
   w.base_of_code                   = src.base_of_code
   w.base_of_data                   = src.base_of_data
   w.base_of_bss                    = src.base_of_bss
   w.gpr_mask                       = src.gpr_mask
   w.cpr_mask                       = src.cpr_mask
   w.gp_value                       = src.gp_value

   return
}

_wrap_from_pe32 :: proc(src: ^Image_Optional_Header32) -> (w: Wrapped_Optional_Header) {
   w.magic                          = src.magic
   w.major_linker_version           = src.major_linker_version
   w.minor_linker_version           = src.minor_linker_version
   w.size_of_code                   = src.size_of_code
   w.size_of_initialized_data       = src.size_of_initialized_data
   w.size_of_uninitialized_data     = src.size_of_uninitialized_data
   w.address_of_entry_point         = src.address_of_entry_point
   w.base_of_code                   = src.base_of_code
   w.base_of_data                   = src.base_of_data
   w.image_base                     = u64le(src.image_base)
   w.section_alignment              = src.section_alignment
   w.file_alignment                 = src.file_alignment
   w.major_operating_system_version = src.major_operating_system_version
   w.minor_operating_system_version = src.minor_operating_system_version
   w.major_image_version            = src.major_image_version
   w.minor_image_version            = src.minor_image_version
   w.major_subsystem_version        = src.major_subsystem_version
   w.minor_subsystem_version        = src.minor_subsystem_version
   w.win32_version_value            = src.win32_version_value
   w.size_of_image                  = src.size_of_image
   w.size_of_headers                = src.size_of_headers
   w.check_sum                      = src.check_sum
   w.subsystem                      = src.subsystem
   w.dll_characteristics            = src.dll_characteristics
   w.size_of_stack_reserve          = u64le(src.size_of_stack_reserve)
   w.size_of_stack_commit           = u64le(src.size_of_stack_commit)
   w.size_of_heap_reserve           = u64le(src.size_of_heap_reserve)
   w.size_of_heap_commit            = u64le(src.size_of_heap_commit)
   w.loader_flags                   = src.loader_flags
   w.number_of_rva_and_sizes        = src.number_of_rva_and_sizes

   for dir, i in Image_Data_Directories {
      w.data_directory[dir] = src.data_directory[dir]
   }

   return w
}

_wrap_from_pe64 :: proc(src: ^Image_Optional_Header64) -> (w: Wrapped_Optional_Header) {
   w.magic                          = src.magic
   w.major_linker_version           = src.major_linker_version
   w.minor_linker_version           = src.minor_linker_version
   w.size_of_code                   = src.size_of_code
   w.size_of_initialized_data       = src.size_of_initialized_data
   w.size_of_uninitialized_data     = src.size_of_uninitialized_data
   w.address_of_entry_point         = src.address_of_entry_point
   w.base_of_code                   = src.base_of_code
   w.image_base                     = src.image_base
   w.section_alignment              = src.section_alignment
   w.file_alignment                 = src.file_alignment
   w.major_operating_system_version = src.major_operating_system_version
   w.minor_operating_system_version = src.minor_operating_system_version
   w.major_image_version            = src.major_image_version
   w.minor_image_version            = src.minor_image_version
   w.major_subsystem_version        = src.major_subsystem_version
   w.minor_subsystem_version        = src.minor_subsystem_version
   w.win32_version_value            = src.win32_version_value
   w.size_of_image                  = src.size_of_image
   w.size_of_headers                = src.size_of_headers
   w.check_sum                      = src.check_sum
   w.subsystem                      = src.subsystem
   w.dll_characteristics            = src.dll_characteristics
   w.size_of_stack_reserve          = src.size_of_stack_reserve
   w.size_of_stack_commit           = src.size_of_stack_commit
   w.size_of_heap_reserve           = src.size_of_heap_reserve
   w.size_of_heap_commit            = src.size_of_heap_commit
   w.loader_flags                   = src.loader_flags
   w.number_of_rva_and_sizes        = src.number_of_rva_and_sizes

   for dir, i in Image_Data_Directories {
      w.data_directory[dir] = src.data_directory[dir]
   }

   return
}

read_optional_rom :: proc(r: ^Binary_Reader, opt_size: int, outh: ^Image_ROM_Optional_Header) -> bool {
   if size_of(outh^) > opt_size {
      return false
   }
   if !reader_read_n(r, cast(rawptr)&outh^, size_of(outh^)) {
      return false
   }
   pad := opt_size - size_of(outh^)
   if pad > 0 {
      reader_seek(r, pad, .Current)
   }
   return true
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

read_optional_pe32 :: proc(r: ^Binary_Reader, opt_size: int, outh: ^Image_Optional_Header32) -> bool {
   base_size := base_optional_header_size(Image_Optional_Header32)
   if base_size > opt_size {
      return false
   }

   if !reader_read_n(r, cast(rawptr)&outh^, base_size) {
      return false
   }

   if !validate_optional_header32(outh, opt_size) {
      return false
   }

   remaining := opt_size - base_size
   want_dirs := cast(int) outh.number_of_rva_and_sizes
   need_bytes := want_dirs * size_of(Image_Data_Directory)

   if need_bytes > remaining {
      return false
   }

   for dir, idx in Image_Data_Directories {
      if idx >= want_dirs {
         break
      }
      if !reader_read_n(r, cast(rawptr)&outh.data_directory[dir], size_of(Image_Data_Directory)) {
         return false
      }
   }

   pad := remaining - need_bytes
   if pad > 0 {
      reader_seek(r, pad, .Current)
   }

   return true
}

read_optional_pe32_plus :: proc(r: ^Binary_Reader, opt_size: int, outh: ^Image_Optional_Header64) -> bool {
   base_size := base_optional_header_size(Image_Optional_Header64)

   if base_size > opt_size {
      return false
   }

   if !reader_read_n(r, cast(rawptr)&outh^, base_size) {
      return false
   }

   if !validate_optional_header64(outh, opt_size) {
      return false
   }

   remaining := opt_size - base_size
   want_dirs := cast(int) outh.number_of_rva_and_sizes
   need_bytes := want_dirs * size_of(Image_Data_Directory)

   if need_bytes > remaining {
      return false
   }

   for dir, idx in Image_Data_Directories {
      if idx >= want_dirs {
         break
      }
      if !reader_read_n(r, cast(rawptr)&outh.data_directory[dir], size_of(Image_Data_Directory)) {
         return false
      }
   }

   pad := remaining - need_bytes
   if pad > 0 {
      reader_seek(r, pad, .Current)
   }

   return true
}

read_optional_header :: proc(img: ^Decoded_Image, r: ^Binary_Reader) -> bool {
   magic := reader_read_le(r, u16le) or_return

   reader_seek(r, -size_of(magic), .Current)

   opt_size := cast(int) img.file_header.size_of_optional_header

   if magic == IMAGE_OPTIONAL_HEADER_MAGIC_ROM {
      rom: Image_ROM_Optional_Header
      read_optional_rom(r, opt_size, &rom) or_return
      img.optional_header = _wrap_from_rom(&rom)
      return true
   }

   if magic == IMAGE_OPTIONAL_HEADER_MAGIC_PE32 {
      h32: Image_Optional_Header32
      read_optional_pe32(r, opt_size, &h32) or_return
      img.optional_header = _wrap_from_pe32(&h32)
      return true
   }

   if magic == IMAGE_OPTIONAL_HEADER_MAGIC_PE64{
      h64: Image_Optional_Header64
      read_optional_pe32_plus(r, opt_size, &h64) or_return
      img.optional_header = _wrap_from_pe64(&h64)
      return true
   }

   return false
}

read_nt_headers :: proc(img: ^Decoded_Image, r: ^Binary_Reader) -> bool {
   signature := reader_read_le(r, u32le) or_return

   if signature != IMAGE_NT_SIGNATURE {
      return false
   }

   read_file_header(img, r)     or_return
   read_optional_header(img, r) or_return

   return true
}

get_directory_checked :: proc(h: ^Wrapped_Optional_Header, dir: Image_Data_Directories) -> (Image_Data_Directory, bool) {
   if h.magic == IMAGE_OPTIONAL_HEADER_MAGIC_ROM {
      return {}, false
   }

   if cast(int) dir >= cast(int) h.number_of_rva_and_sizes {
      return {}, false
   }

   entry := h.data_directory[dir]

   if entry.size == 0 || entry.virtual_address == 0 {
      return {}, false
   }

   return entry, true
}
