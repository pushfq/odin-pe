package pe

import "core:os"
import "core:bytes"
import "core:mem"
import "core:mem/virtual"

Image_Decode_Error :: enum {
   IO_ERROR,
   BAD_DOS_HEADER,
   BAD_NT_HEADERS,
   BAD_SECTION,
}

Decoded_Optional_Header :: union {
   Image_Optional_Header32,
   Image_Optional_Header64,
}

Decoded_Section_List :: struct {
   section_pool: []u8,
   headers:      [dynamic]Image_Section_Header,
}

Decoded_Image :: struct {
   dos_header:      Image_Dos_Header,
   file_header:     Image_File_Header,
   optional_header: Decoded_Optional_Header,
   section_list:    Decoded_Section_List,
}

@private
_read_into_checked :: proc(rd: ^bytes.Reader, out: ^$T) -> bool {
   n, _ := bytes.reader_read(rd, mem.ptr_to_bytes(out))
   return n == size_of(T)
}

@private
_read_dos_header :: proc(img: ^Decoded_Image, rd: ^bytes.Reader) -> bool {
   dos_header: Image_Dos_Header

   if !_read_into_checked(rd, &dos_header) || !is_valid_dos_header(&dos_header, len(rd.s)){
      return false
   }

   // Pure DOS images are out-of-scope.
   if dos_header.e_lfanew == 0 {
      return false
   }

   img.dos_header = dos_header

   // `is_valid_dos_header` asserts that we can do this.
   bytes.reader_seek(rd, cast(i64) dos_header.e_lfanew, .Start)

   return true
}

@private
_read_file_header :: proc(img: ^Decoded_Image, rd: ^bytes.Reader) -> bool {
   file_header: Image_File_Header
   if !_read_into_checked(rd, &file_header) {
      return false
   }

   validate_machine := proc(hdr: ^Image_File_Header) -> (result: bool) {
      for machine in Image_File_Machine {
         result |= machine == hdr.machine
      }
      return
   }

   // Ensure that the machine identifier is sane.
   if !validate_machine(&file_header) {
      return false
   }

   opt_start := cast(int) rd.i
   opt_size  := cast(int) file_header.size_of_optional_header

   // rd.i + SizeOfOptionalHeader must not exceed len(rd.s)
   if opt_size < 0 || opt_start < 0 || opt_start + opt_size > len(rd.s) {
      return false
   }

   // COFF symbol table pointers (image files generally have these zeroed; OBJs may not).
   // If present, ensure PointerToSymbolTable is within the file (coarse check).
   if file_header.pointer_to_symbol_table != 0 {
      symbol_table_offset := cast(int) file_header.pointer_to_symbol_table

      // `pointer_to_symbol_table` must be within file.
      if symbol_table_offset >= len(rd.s) {
         return false
      }

      symbol_count := cast(int) file_header.number_of_symbols

      // Check `number_of_symbols` * sizeof(COFF_Symbol) fits within the file as well.
      if symbol_table_offset + symbol_count * size_of(Image_Symbol) >= len(rd.s) {
         return false
      }
   }

   img.file_header = file_header

   return true
}

@private
_read_optional_header :: proc(img: ^Decoded_Image, rd: ^bytes.Reader) -> bool {
   // Peek magic
   magic: u16le
   if !_read_into_checked(rd, &magic) {
      return false
   }

   bytes.reader_seek(rd, -cast(i64) size_of(magic), .Current)

   opt_size := cast(int) img.file_header.size_of_optional_header
   if opt_size < 0 {
      return false
   }

   // PE32
   if magic == IMAGE_OPTIONAL_HEADER_MAGIC_PE32 {
      header32: Image_Optional_Header32

      base_size := base_optional_header_size(Image_Optional_Header32)
      if base_size > opt_size {
         return false
      }

      base_slice := mem.ptr_to_bytes(&header32)[0:base_size]

      // Read base fields
      if n, _ := bytes.reader_read(rd, base_slice); n != base_size {
         return false
      }

      // Validation enforces `number_of_rva_and_sizes` and overall `size_of_optional_header` sanity.
      if !validate_optional_header32(&header32, opt_size) {
         return false
      }

      remaining := opt_size - base_size
      if remaining < 0 {
         return false
      }

      want_dirs := cast(int) header32.number_of_rva_and_sizes
      need_bytes := want_dirs * size_of(Image_Data_Directory)

      if need_bytes > remaining {
         return false
      }

      for dir, i in Image_Data_Directories {
         if i >= want_dirs {
            break
         }

         if !_read_into_checked(rd, &header32.data_directory[dir]) {
            return false
         }
      }

      // Skip any trailing padding in the optional header.
      pad := remaining - need_bytes
      if pad > 0 {
         if _, err := bytes.reader_seek(rd, cast(i64) pad, .Current); err != nil {
            return false
         }
      }

      img.optional_header = header32
      return true
   }

   // PE32+
   if magic == IMAGE_OPTIONAL_HEADER_MAGIC_PE64 {
      header64: Image_Optional_Header64

      base_size := base_optional_header_size(Image_Optional_Header64)
      if base_size > opt_size {
         return false
      }

      base_slice := mem.ptr_to_bytes(&header64)[0:base_size]

      // Read base fields
      if n, _ := bytes.reader_read(rd, base_slice); n != base_size {
         return false
      }

      if !validate_optional_header64(&header64, opt_size) {
         return false
      }

      remaining := opt_size - base_size
      if remaining < 0 {
         return false
      }

      want_dirs := cast(int) header64.number_of_rva_and_sizes
      need_bytes := want_dirs * size_of(Image_Data_Directory)

      if need_bytes > remaining {
         return false
      }

      for dir, i in Image_Data_Directories {
         if i >= want_dirs {
            break
         }

         if !_read_into_checked(rd, &header64.data_directory[dir]) {
            return false
         }
      }

      pad := remaining - need_bytes
      if pad > 0 {
         if _, err := bytes.reader_seek(rd, cast(i64) pad, .Current); err != nil {
            return false
         }
      }

      img.optional_header = header64
      return true
   }

   return false
}

@private
_read_nt_headers :: proc(img: ^Decoded_Image, rd: ^bytes.Reader) -> bool {
   probe: u32le
   _read_into_checked(rd, &probe) // This cannot fail because `is_valid_dos_header` asserts that we can do this.

   if probe != IMAGE_NT_SIGNATURE {
      return false
   }

   if !_read_file_header(img, rd) {
      return false
   }

   if !_read_optional_header(img, rd) {
      return false
   }

   return true
}

@private
_read_section_headers :: proc(img: ^Decoded_Image, rd: ^bytes.Reader) -> bool {
   want_sections := cast(int) img.file_header.number_of_sections
   if want_sections < 0 {
      return false
   }

   // Ensure the entire section table fits in the remaining file bytes.
   remaining := cast(int)(len(rd.s) - cast(int) rd.i)
   table_bytes := want_sections * size_of(Image_Section_Header)
   if table_bytes < 0 || table_bytes > remaining {
      return false
   }

   total_size: int
   for i in 0 ..< want_sections {
      sh: Image_Section_Header
      if !_read_into_checked(rd, &sh) {
         return false
      }

      // If the section has initialized data on disk, the span must be in-bounds.
      if sh.size_of_raw_data > 0 {
         start := cast(int) sh.pointer_to_raw_data
         size  := cast(int) sh.size_of_raw_data

         if start < 0 || size < 0 || start + size > len(rd.s) {
            return false
         }

         total_size += size
      }

      append(&img.section_list.headers, sh)
   }

   img.section_list.section_pool = make([]u8, total_size)

   return true
}

@private
_copy_section_data :: proc(img: ^Decoded_Image, rd: ^bytes.Reader) -> bool {
   // `_read_section_headers` initializes the pool for us.
   pool := img.section_list.section_pool

   pool_off := 0
   for i in 0 ..< len(img.section_list.headers) {
      sh := img.section_list.headers[i]
      size  := cast(int) sh.size_of_raw_data
      start := cast(int) sh.pointer_to_raw_data

      // Skip sections without initialized raw data.
      if size <= 0 {
         continue
      }

      src := rd.s[start:start+size]

      if pool_off + size > len(pool) {
         return false
      }

      dst := pool[pool_off:pool_off+size]

      mem.copy(raw_data(dst), raw_data(src), size)

      pool_off += size
   }

   return true
}

@private
_read_sections :: proc(img: ^Decoded_Image, rd: ^bytes.Reader) -> bool {
   if !_read_section_headers(img, rd) {
      return false
   }

   return _copy_section_data(img, rd)
}

image_load_from_memory :: proc(data: []byte) -> (result: Decoded_Image, err: Image_Decode_Error) {
   rd: bytes.Reader

   bytes.reader_init(&rd, data)

   if !_read_dos_header(&result, &rd) {
      return {}, .BAD_DOS_HEADER
   }

   if !_read_nt_headers(&result, &rd) {
      return {}, .BAD_NT_HEADERS
   }

   if !_read_sections(&result, &rd) {
      return {}, .BAD_SECTION
   }

   return
}

image_load_from_file :: proc(file_path: string) -> (Decoded_Image, Image_Decode_Error) {
   arena: virtual.Arena

   if virtual.arena_init_growing(&arena) == nil {
      defer virtual.arena_destroy(&arena)

      data, success := os.read_entire_file(file_path, virtual.arena_allocator(&arena))
      if success {
         return image_load_from_memory(data)
      }
   }

   return {}, .IO_ERROR
}

image_destroy :: proc(img: ^Decoded_Image) {
   delete(img.section_list.headers)
   delete(img.section_list.section_pool)
}
