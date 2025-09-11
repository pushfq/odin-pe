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
   BAD_RELOCATION,
}

Decoded_Optional_Header :: union {
   Image_Optional_Header32,
   Image_Optional_Header64,
}

Decoded_Relocation :: struct {
   type: Image_Based_Relocation_Type,
   rva:  int,
}

Decoded_Image :: struct {
   file_data:       []u8,
   arena:           virtual.Arena,
   was_allocated:   bool,

   dos_header:      Image_Dos_Header,
   file_header:     Image_File_Header,
   optional_header: Decoded_Optional_Header,

   relocations:     [dynamic]Decoded_Relocation,
   section_headers: [dynamic]Image_Section_Header,
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
         size := cast(int) sh.size_of_raw_data

         if start < 0 || size < 0 || start + size > len(rd.s) {
            return false
         }

         total_size += size
      }

      append(&img.section_headers, sh)
   }

   return true
}

@private
_read_based_relocations :: proc(img: ^Decoded_Image, rd: ^bytes.Reader) -> bool {
   read_u16_le := #force_inline proc "contextless" (b: []u8) -> u16 {
      return cast(u16)(b[0]) | (cast(u16)(b[1]) << 8)
   }

   read_u32_le := #force_inline proc "contextless" (b: []u8) -> u32 {
      return cast(u32)(b[0]) | (cast(u32)(b[1]) << 8) | (cast(u32)(b[2]) << 16) | (cast(u32)(b[3]) << 24)
   }

   // If relocations were stripped, nothing to read (valid image if it loads at preferred base).
   // IMAGE_FILE_RELOCS_STRIPPED indicates no base relocations present.
   if .RELOCS_STRIPPED in img.file_header.characteristics {
      return true
   }

   // @TODO(Sonny): Just read this from the directory entry.
   RELOC_SECTION_NAME :: ".reloc\x00\x00"

   reloc_section: ^Image_Section_Header
   for &section in img.section_headers {
      if section.name == RELOC_SECTION_NAME {
         reloc_section = &section
      }
   }

   if reloc_section == nil {
      return true
   }

   data := image_get_section_data_from_header(img, reloc_section)
   if len(data) == 0 {
      // Empty .reloc is permissible; nothing to do.
      return true
   }

   off := 0
   for {
      if off + 8 > len(data) {
         break
      }

      page_rva := read_u32_le(data[off+0 : off+4])
      size_of_block := read_u32_le(data[off+4 : off+8])

      if size_of_block < 8 || size_of_block == 0{
         break
      }

      if off + cast(int) size_of_block > len(data) {
         continue
      }

      entries_bytes := cast(int) size_of_block - 8
      if (entries_bytes & 1) != 0 {
         continue
      }

      entry_count := entries_bytes / 2
      entries_base := off + 8

      for i := 0; i < entry_count; i += 1 {
         e := read_u16_le(data[entries_base + 2*i : entries_base + 2*i + 2])

         rel_type := cast(Image_Based_Relocation_Type)((e >> 12) & 0xF)
         rel_off12 := cast(int)(e & 0x0FFF)

         if rel_type == .ABSOLUTE {
            continue
         }

         reloc: Decoded_Relocation
         reloc.type = rel_type
         reloc.rva  = cast(int) page_rva + rel_off12

         append(&img.relocations, reloc)
      }

      off += cast(int) size_of_block
   }

   return true
}

image_get_section_data_from_header :: proc(img: ^Decoded_Image, sh: ^Image_Section_Header) -> []u8 {
   return img.file_data[sh.pointer_to_raw_data:sh.pointer_to_raw_data+sh.size_of_raw_data]
}

image_load_from_memory :: proc(data: []byte) -> (result: Decoded_Image, err: Image_Decode_Error) {
   rd: bytes.Reader

   bytes.reader_init(&rd, data)

   result.file_data = data

   if !_read_dos_header(&result, &rd) {
      return {}, .BAD_DOS_HEADER
   }

   if !_read_nt_headers(&result, &rd) {
      return {}, .BAD_NT_HEADERS
   }

   if !_read_section_headers(&result, &rd) {
      return {}, .BAD_SECTION
   }

   if !_read_based_relocations(&result, &rd) {
      return {}, .BAD_RELOCATION
   }

   return
}

image_load_from_file :: proc(file_path: string) -> (Decoded_Image, Image_Decode_Error) {
   arena: virtual.Arena

   if virtual.arena_init_growing(&arena) == nil {
      data, success := os.read_entire_file(file_path, virtual.arena_allocator(&arena))

      if success {
         result, err := image_load_from_memory(data)

         result.arena = arena
         result.was_allocated = true

         return result, err
      }
   }

   return {}, .IO_ERROR
}

image_destroy :: proc(img: ^Decoded_Image) {
   delete(img.relocations)
   delete(img.section_headers)

   if img.was_allocated {
      virtual.arena_destroy(&img.arena)
   }
}
