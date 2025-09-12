package pe

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

Base_Relocation_Entry :: struct {
   type: Image_Based_Relocation_Type,
   virtual_address: u64,
}

read_based_relocations :: proc(img: ^Decoded_Image, r: ^Binary_Reader) -> bool {
   if .RELOCS_STRIPPED in img.file_header.characteristics {
      return true
   }

   dir := get_directory_checked(&img.optional_header, .BASERELOC)   or_return
   off := va_to_offset(img.section_headers[:], dir.virtual_address) or_return

   reader_seek(r, cast(int) off, .Start)

   for {
      if !reader_ensure_n(r, 8) {
         break
      }

      page_rva := reader_read_le(r, u32le) or_return
      size_of_block := reader_read_le(r, u32le) or_return

      if size_of_block < 8 || size_of_block == 0 {
         break
      }

      if !reader_ensure_n(r, cast(int) size_of_block) {
         continue
      }

      entries_bytes := cast(int) size_of_block - 8
      if (entries_bytes & 1) != 0 {
         continue
      }

      entry_count := entries_bytes / 2
      for i := 0; i < entry_count; i += 1 {
         entry := reader_read_le(r, u16le) or_return
         rel_type := cast(Image_Based_Relocation_Type)((entry >> 12) & 0xF)
         rel_off12 := cast(u64)(entry & 0x0FFF)

         if rel_type == .ABSOLUTE {
            continue
         }

         reloc: Base_Relocation_Entry
         reloc.type = rel_type
         reloc.virtual_address = cast(u64) page_rva + rel_off12

         append(&img.base_relocations, reloc)
      }
   }

   return true
}
