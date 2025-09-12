package pe

import "core:os"
import "core:mem"
import "core:mem/virtual"

Decoded_Image :: struct {
   file_data:     []u8,
   was_allocated: bool,
   arena:         virtual.Arena,

   dos_header:      Image_DOS_Header,
   file_header:     Image_File_Header,
   optional_header: Wrapped_Optional_Header,


   section_headers:  [dynamic]Image_Section_Header,
   base_relocations: [dynamic]Base_Relocation_Entry,
}

image_load_from_memory :: proc(data: []byte) -> (result: Decoded_Image, ok: bool) {
   r := reader_create(data)

   read_dos_header        (&result, &r) or_return
   read_nt_headers        (&result, &r) or_return
   read_section_headers   (&result, &r) or_return
   read_based_relocations (&result, &r) or_return

   return result, true
}

image_load_from_file :: proc(file_path: string) -> (Decoded_Image, bool) {
   arena: virtual.Arena
   if virtual.arena_init_growing(&arena) != nil {
      return {}, false
   }

   data, success := os.read_entire_file(file_path, virtual.arena_allocator(&arena))
   if !success {
      return {}, false
   }

   result, err := image_load_from_memory(data)
   result.arena = arena
   result.was_allocated = true
   return result, err
}

image_destroy :: proc(img: ^Decoded_Image) {
   delete(img.section_headers)
   delete(img.base_relocations)

   if img.was_allocated {
      virtual.arena_destroy(&img.arena)
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
