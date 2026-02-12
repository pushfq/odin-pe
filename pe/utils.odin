package pe

import "base:intrinsics"

checked_ptr :: proc(data: []u8, #any_int offset: int, $T: typeid) -> (ptr: ^T, ok: bool) {
	end, ov := intrinsics.overflow_add(offset, size_of(T))
	if ov || end > len(data) {
		return nil, false
	}
	return cast(^T)intrinsics.ptr_offset(raw_data(data), offset), true
}

speculative_test :: proc(data: []u8, #any_int offset: int, expected: $T) -> bool {
	ptr := checked_ptr(data, offset, T) or_return
	return ptr^ == expected
}

align_up :: #force_inline proc "contextless" (value, alignment: $T) -> T {
	mask := alignment - 1
	return (value + mask) & ~mask
}

align_down :: #force_inline proc "contextless" (value, alignment: $T) -> T {
	return value & ~(alignment - 1)
}

is_aligned :: #force_inline proc "contextless" (value, alignment: $T) -> bool {
	return (value & (alignment - 1)) == 0
}

is_pow2 :: #force_inline proc "contextless" (v: $T) -> bool {
	return v != 0 && (v & (v - 1)) == 0
}
