package pe

import "core:mem"
import "core:io"
import "base:intrinsics"

Binary_Reader :: struct {
   i: int,
   s: []byte,
}

reader_create :: proc(data: []byte) -> Binary_Reader {
   return Binary_Reader{ 0, data }
}

reader_read_le :: proc(
   r: ^Binary_Reader,
   $T: typeid
) -> (result: T, ok: bool)
   where intrinsics.type_is_endian_little(T)
{
   needed_bytes :: size_of(T)

   if r.i + needed_bytes > len(r.s) {
      return 0, false
   }

   #unroll for j in 0..<needed_bytes {
      result |= (cast(T)(r.s[r.i+j]) << uint(j*8))
   }

   r.i += needed_bytes
   return result, true
}

reader_read_n :: proc(
   r: ^Binary_Reader,
   data: rawptr,
   size: int,
) -> (ok: bool)
{
   if len(r.s) - r.i < size {
      return false
   }

   mem.copy(data, raw_data(r.s[r.i:]), size)
   r.i += size

   return true
}

reader_ensure_n :: proc(r: ^Binary_Reader, n: int) -> bool {
   return r.i + n < len(r.s)
}

reader_seek :: proc(
   r: ^Binary_Reader,
   offset: int,
   whence: io.Seek_From
) -> (pos: int, err: io.Error)
{
   abs: int
   switch whence {
   case .Start:
      abs = offset
   case .Current:
      abs = r.i + offset
   case .End:
      abs = int(len(r.s)) + offset
   case: return 0, .Invalid_Whence
   }
   if abs < 0 {
      return 0, .Invalid_Offset
   }
   r.i = abs
   return pos, nil
}
