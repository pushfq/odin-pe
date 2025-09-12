package pe

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

// Flags are also apart of the `characteristics` field... just without the alignment bits!
Image_Section_Flags :: distinct bit_set[Image_Section_Flag; Image_Section_Characteristics]

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

section_name :: proc(h: ^Image_Section_Header) -> []u8 {
   len: int
   for b in h.name {
      if b == '\x00' {
         break
      }
      len += 1
   }

   return h.name[:len]
}

section_alignment :: proc "contextless" (characteristics: Image_Section_Characteristics) -> int {
   align_bits := characteristics & IMAGE_SECTION_ALIGN_MASK

   if align_bits != 0 {
      return 1 << ((align_bits >> 20) - 1)
   }

   return 16
}

section_flags :: proc "contextless" (characteristics: Image_Section_Characteristics) -> Image_Section_Flags {
   return transmute(Image_Section_Flags) (characteristics & ~IMAGE_SECTION_ALIGN_MASK)
}

read_section_headers :: proc(img: ^Decoded_Image, r: ^Binary_Reader) -> bool {
   want_sections := cast(int) img.file_header.number_of_sections
   if want_sections < 0 {
      return false
   }

   for i in 0 ..< want_sections {
      sh: Image_Section_Header

      reader_read_n(r, &sh, size_of(sh)) or_return

      if sh.size_of_raw_data > 0 {
         start, size := cast(int) sh.pointer_to_raw_data, cast(int) sh.size_of_raw_data
         if start + size > len(r.s) {
            return false
         }
      }

      append(&img.section_headers, sh)
   }

   return true
}
