package pe

import "core:os"
import "core:mem"
import "core:mem/virtual"

Decoded_Image :: struct {
   file_data:     []u8,
   owns_mapping:  bool,

   dos_header:      Image_DOS_Header,
   file_header:     Image_File_Header,
   optional_header: Wrapped_Optional_Header,

   section_headers:  [dynamic]Image_Section_Header,
   base_relocations: [dynamic]Base_Relocation_Entry,
}

image_load_from_memory :: proc(img: ^Decoded_Image, allocator := context.allocator) -> bool {
   context.allocator = allocator

   r := reader_create(img.file_data)

   read_dos_header(img, &r) or_return
   read_nt_headers(img, &r) or_return
   read_section_headers(img, &r) or_return
   read_based_relocations(img, &r) or_return

   return true
}

image_load_from_file :: proc(file_path: string, allocator := context.allocator) -> (result: Decoded_Image, err: bool) {
   data, map_err := virtual.map_file_from_path(file_path, {.Read})
   if map_err != nil {
      return {}, false
   }

   result.file_data = data
   result.owns_mapping = true

   image_load_from_memory(&result, allocator) or_return

   return result, true
}

image_destroy :: proc(img: ^Decoded_Image) {
   delete(img.section_headers)
   delete(img.base_relocations)

   if img.owns_mapping {
      virtual.release(raw_data((img.file_data)), len(img.file_data))
   }
}

image_va_to_offset :: proc(img: ^Decoded_Image, #any_int va: u32) -> (offset: u32, ok: bool) {
   for sh in img.section_headers {
      begin := cast(u32) sh.virtual_address
      end := cast(u32)(sh.virtual_address + sh.size_of_raw_data)

      if begin >= va && va <= end {
         return cast(u32) sh.pointer_to_raw_data + (va - begin), true
      }
   }

   return 0, false
}

image_section_view :: proc(img: ^Decoded_Image, sh: ^Image_Section_Header) -> []u8 {
   data := cast(int) sh.pointer_to_raw_data
   size := cast(int) sh.size_of_raw_data

   return img.file_data[data:data+size]
}
