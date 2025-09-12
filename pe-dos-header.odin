package pe

IMAGE_DOS_SIGNATURE :: u16le(0x5A4D)

Image_DOS_Header :: struct #align(2) {
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

is_valid_dos_header :: proc(h: ^Image_DOS_Header, stream_size: int) -> bool {
   LFANEW_PROBE_SIZE :: size_of(u32le)

   if h == nil || stream_size < size_of(Image_DOS_Header) {
      return false
   }

   if h.e_magic != IMAGE_DOS_SIGNATURE || h.e_lfanew < 0 {
      return false
   }

   if h.e_lfanew != 0 {
      if h.e_lfanew < size_of(Image_DOS_Header) {
         return false
      }

      if cast(int) h.e_lfanew > stream_size - LFANEW_PROBE_SIZE {
         return false
      }
   }

   return true
}

read_dos_header :: proc(img: ^Decoded_Image, r: ^Binary_Reader) -> bool {
   dos_header: Image_DOS_Header

   if !reader_read_n(r, &dos_header, size_of(dos_header)) || !is_valid_dos_header(&dos_header, len(r.s)){
      return false
   }

   if dos_header.e_lfanew == 0 { // Pure DOS images are out-of-scope.
      return false
   }

   img.dos_header = dos_header

   reader_seek(r, cast(int) dos_header.e_lfanew, .Start)

   return true
}
