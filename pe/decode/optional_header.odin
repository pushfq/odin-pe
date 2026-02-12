package pe_decode

import "base:intrinsics"

import "core:encoding/endian"
import "core:mem"

import ".."
import "../format"

PE32_FIXED_SIZE :: size_of(format.Image_Optional_Header32) - DATA_DIR_ARRAY_SIZE
PE64_FIXED_SIZE :: size_of(format.Image_Optional_Header64) - DATA_DIR_ARRAY_SIZE

MAX_DATA_DIRS :: len(format.Image_Data_Directories)
DATA_DIR_ARRAY_SIZE :: size_of([MAX_DATA_DIRS]format.Image_Data_Directory)

Field_Off :: struct {
	src_off: u32,
	dst_off: u32,
}

Field_Groups :: struct {
	u32_to_u64s: []Field_Off,
	u64s:        []Field_Off,
	u32s:        []Field_Off,
	u16s:        []Field_Off,
	u8s:         []Field_Off,
}

// odinfmt: disable
@(rodata)
pe32_u32_to_u64 := [?]Field_Off{
   {u32(offset_of(format.Image_Optional_Header32, image_base)),                     u32(offset_of(pe.Optional_Header, image_base))},
   {u32(offset_of(format.Image_Optional_Header32, size_of_stack_reserve)),          u32(offset_of(pe.Optional_Header, size_of_stack_reserve))},
   {u32(offset_of(format.Image_Optional_Header32, size_of_stack_commit)),           u32(offset_of(pe.Optional_Header, size_of_stack_commit))},
   {u32(offset_of(format.Image_Optional_Header32, size_of_heap_reserve)),           u32(offset_of(pe.Optional_Header, size_of_heap_reserve))},
   {u32(offset_of(format.Image_Optional_Header32, size_of_heap_commit)),            u32(offset_of(pe.Optional_Header, size_of_heap_commit))},
}

@(rodata)
pe32_u32 := [?]Field_Off{
   {u32(offset_of(format.Image_Optional_Header32, address_of_entry_point)),         u32(offset_of(pe.Optional_Header, address_of_entry_point))},
   {u32(offset_of(format.Image_Optional_Header32, size_of_code)),                   u32(offset_of(pe.Optional_Header, size_of_code))},
   {u32(offset_of(format.Image_Optional_Header32, size_of_initialized_data)),       u32(offset_of(pe.Optional_Header, size_of_initialized_data))},
   {u32(offset_of(format.Image_Optional_Header32, size_of_uninitialized_data)),     u32(offset_of(pe.Optional_Header, size_of_uninitialized_data))},
   {u32(offset_of(format.Image_Optional_Header32, base_of_code)),                   u32(offset_of(pe.Optional_Header, base_of_code))},
   {u32(offset_of(format.Image_Optional_Header32, base_of_data)),                   u32(offset_of(pe.Optional_Header, base_of_data))},
   {u32(offset_of(format.Image_Optional_Header32, section_alignment)),              u32(offset_of(pe.Optional_Header, section_alignment))},
   {u32(offset_of(format.Image_Optional_Header32, file_alignment)),                 u32(offset_of(pe.Optional_Header, file_alignment))},
   {u32(offset_of(format.Image_Optional_Header32, size_of_image)),                  u32(offset_of(pe.Optional_Header, size_of_image))},
   {u32(offset_of(format.Image_Optional_Header32, size_of_headers)),                u32(offset_of(pe.Optional_Header, size_of_headers))},
   {u32(offset_of(format.Image_Optional_Header32, check_sum)),                      u32(offset_of(pe.Optional_Header, check_sum))},
   {u32(offset_of(format.Image_Optional_Header32, win32_version_value)),            u32(offset_of(pe.Optional_Header, win32_version_value))},
   {u32(offset_of(format.Image_Optional_Header32, loader_flags)),                   u32(offset_of(pe.Optional_Header, loader_flags))},
   {u32(offset_of(format.Image_Optional_Header32, number_of_rva_and_sizes)),        u32(offset_of(pe.Optional_Header, number_of_rva_and_sizes))},
}

@(rodata)
pe32_u16 := [?]Field_Off{
   {u32(offset_of(format.Image_Optional_Header32, magic)),                          u32(offset_of(pe.Optional_Header, magic))},
   {u32(offset_of(format.Image_Optional_Header32, major_operating_system_version)), u32(offset_of(pe.Optional_Header, major_operating_system_version))},
   {u32(offset_of(format.Image_Optional_Header32, minor_operating_system_version)), u32(offset_of(pe.Optional_Header, minor_operating_system_version))},
   {u32(offset_of(format.Image_Optional_Header32, major_image_version)),            u32(offset_of(pe.Optional_Header, major_image_version))},
   {u32(offset_of(format.Image_Optional_Header32, minor_image_version)),            u32(offset_of(pe.Optional_Header, minor_image_version))},
   {u32(offset_of(format.Image_Optional_Header32, major_subsystem_version)),        u32(offset_of(pe.Optional_Header, major_subsystem_version))},
   {u32(offset_of(format.Image_Optional_Header32, minor_subsystem_version)),        u32(offset_of(pe.Optional_Header, minor_subsystem_version))},
   {u32(offset_of(format.Image_Optional_Header32, subsystem)),                      u32(offset_of(pe.Optional_Header, subsystem))},
   {u32(offset_of(format.Image_Optional_Header32, dll_characteristics)),            u32(offset_of(pe.Optional_Header, dll_characteristics))},
}

@(rodata)
pe32_u8 := [?]Field_Off{
   {u32(offset_of(format.Image_Optional_Header32, major_linker_version)),           u32(offset_of(pe.Optional_Header, major_linker_version))},
   {u32(offset_of(format.Image_Optional_Header32, minor_linker_version)),           u32(offset_of(pe.Optional_Header, minor_linker_version))},
}

@(rodata)
pe64_u64 := [?]Field_Off{
   {u32(offset_of(format.Image_Optional_Header64, image_base)),                     u32(offset_of(pe.Optional_Header, image_base))},
   {u32(offset_of(format.Image_Optional_Header64, size_of_stack_reserve)),          u32(offset_of(pe.Optional_Header, size_of_stack_reserve))},
   {u32(offset_of(format.Image_Optional_Header64, size_of_stack_commit)),           u32(offset_of(pe.Optional_Header, size_of_stack_commit))},
   {u32(offset_of(format.Image_Optional_Header64, size_of_heap_reserve)),           u32(offset_of(pe.Optional_Header, size_of_heap_reserve))},
   {u32(offset_of(format.Image_Optional_Header64, size_of_heap_commit)),            u32(offset_of(pe.Optional_Header, size_of_heap_commit))},
}

@(rodata)
pe64_u32 := [?]Field_Off{
   {u32(offset_of(format.Image_Optional_Header64, address_of_entry_point)),         u32(offset_of(pe.Optional_Header, address_of_entry_point))},
   {u32(offset_of(format.Image_Optional_Header64, size_of_code)),                   u32(offset_of(pe.Optional_Header, size_of_code))},
   {u32(offset_of(format.Image_Optional_Header64, size_of_initialized_data)),       u32(offset_of(pe.Optional_Header, size_of_initialized_data))},
   {u32(offset_of(format.Image_Optional_Header64, size_of_uninitialized_data)),     u32(offset_of(pe.Optional_Header, size_of_uninitialized_data))},
   {u32(offset_of(format.Image_Optional_Header64, base_of_code)),                   u32(offset_of(pe.Optional_Header, base_of_code))},
   {u32(offset_of(format.Image_Optional_Header64, section_alignment)),              u32(offset_of(pe.Optional_Header, section_alignment))},
   {u32(offset_of(format.Image_Optional_Header64, file_alignment)),                 u32(offset_of(pe.Optional_Header, file_alignment))},
   {u32(offset_of(format.Image_Optional_Header64, size_of_image)),                  u32(offset_of(pe.Optional_Header, size_of_image))},
   {u32(offset_of(format.Image_Optional_Header64, size_of_headers)),                u32(offset_of(pe.Optional_Header, size_of_headers))},
   {u32(offset_of(format.Image_Optional_Header64, check_sum)),                      u32(offset_of(pe.Optional_Header, check_sum))},
   {u32(offset_of(format.Image_Optional_Header64, win32_version_value)),            u32(offset_of(pe.Optional_Header, win32_version_value))},
   {u32(offset_of(format.Image_Optional_Header64, loader_flags)),                   u32(offset_of(pe.Optional_Header, loader_flags))},
   {u32(offset_of(format.Image_Optional_Header64, number_of_rva_and_sizes)),        u32(offset_of(pe.Optional_Header, number_of_rva_and_sizes))},
}

@(rodata)
pe64_u16 := [?]Field_Off{
   {u32(offset_of(format.Image_Optional_Header64, magic)),                          u32(offset_of(pe.Optional_Header, magic))},
   {u32(offset_of(format.Image_Optional_Header64, major_operating_system_version)), u32(offset_of(pe.Optional_Header, major_operating_system_version))},
   {u32(offset_of(format.Image_Optional_Header64, minor_operating_system_version)), u32(offset_of(pe.Optional_Header, minor_operating_system_version))},
   {u32(offset_of(format.Image_Optional_Header64, major_image_version)),            u32(offset_of(pe.Optional_Header, major_image_version))},
   {u32(offset_of(format.Image_Optional_Header64, minor_image_version)),            u32(offset_of(pe.Optional_Header, minor_image_version))},
   {u32(offset_of(format.Image_Optional_Header64, major_subsystem_version)),        u32(offset_of(pe.Optional_Header, major_subsystem_version))},
   {u32(offset_of(format.Image_Optional_Header64, minor_subsystem_version)),        u32(offset_of(pe.Optional_Header, minor_subsystem_version))},
   {u32(offset_of(format.Image_Optional_Header64, subsystem)),                      u32(offset_of(pe.Optional_Header, subsystem))},
   {u32(offset_of(format.Image_Optional_Header64, dll_characteristics)),            u32(offset_of(pe.Optional_Header, dll_characteristics))},
}

@(rodata)
pe64_u8 := [?]Field_Off{
   {u32(offset_of(format.Image_Optional_Header64, major_linker_version)), u32(offset_of(pe.Optional_Header, major_linker_version))},
   {u32(offset_of(format.Image_Optional_Header64, minor_linker_version)), u32(offset_of(pe.Optional_Header, minor_linker_version))},
}

pe32_groups := Field_Groups {
	u32_to_u64s = pe32_u32_to_u64[:],
	u64s        = {},
	u32s        = pe32_u32[:],
	u16s        = pe32_u16[:],
	u8s         = pe32_u8[:],
}

pe64_groups := Field_Groups {
	u32_to_u64s = {},
	u64s        = pe64_u64[:],
	u32s        = pe64_u32[:],
	u16s        = pe64_u16[:],
	u8s         = pe64_u8[:],
}
// odinfmt: enable

transpose_widen :: proc(src_base, dst_base: [^]u8, group: []Field_Off) {
	for f in group {
		src_ptr := mem.ptr_offset(src_base, f.src_off)
		dst_ptr := mem.ptr_offset(dst_base, f.dst_off)

		v := endian.unchecked_get_u32le(src_ptr[:4])
		intrinsics.unaligned_store(cast(^u64)dst_ptr, u64(v))
	}
}

transpose_fixed :: proc(src_base, dst_base: [^]u8, group: []Field_Off, $T: typeid) {
	for f in group {
		src_off := mem.ptr_offset(src_base, f.src_off)
		dst_off := mem.ptr_offset(dst_base, f.dst_off)

		intrinsics.mem_copy(dst_off, src_off, size_of(T))
	}
}

transpose_optional :: proc(src: []u8, groups: Field_Groups) -> pe.Optional_Header {
	dst: pe.Optional_Header

	src_base := raw_data(src)
	dst_base := ([^]u8)(&dst)

	transpose_widen(src_base, dst_base, groups.u32_to_u64s)
	transpose_fixed(src_base, dst_base, groups.u64s, u64)
	transpose_fixed(src_base, dst_base, groups.u32s, u32)
	transpose_fixed(src_base, dst_base, groups.u16s, u16)
	transpose_fixed(src_base, dst_base, groups.u8s, u8)

	return dst
}

validate_header :: proc(header: ^pe.Optional_Header) -> pe.Error {
	fa := header.file_alignment
	sa := header.section_alignment

	if !pe.is_pow2(fa) || fa < format.MIN_FILE_ALIGNMENT || fa > format.MAX_FILE_ALIGNMENT {
		return .Invalid_Header
	}

	if !pe.is_pow2(sa) || sa < fa {
		return .Invalid_Header
	}

	if !pe.is_aligned(header.size_of_headers, fa) ||
	   !pe.is_aligned(header.size_of_image, sa) ||
	   header.size_of_headers >= header.size_of_image {
		return .Invalid_Header
	}

	return nil
}

read_data_directories :: proc(header: ^pe.Optional_Header, dir_data: []u8) {
	dirs := mem.slice_data_cast([]format.Image_Data_Directory, dir_data)
	actual := min(int(header.number_of_rva_and_sizes), MAX_DATA_DIRS, len(dirs))

	for i in 0 ..< actual {
		header.data_directories[format.Image_Data_Directories(i)] = dirs[i]
	}

	header.number_of_rva_and_sizes = u32(actual)
}

validate_data_directories :: proc(header: ^pe.Optional_Header) -> pe.Error {
	for i in 0 ..< header.number_of_rva_and_sizes {
		dir := header.data_directories[format.Image_Data_Directories(i)]

		if dir.size == 0 {
			continue
		}

		_, ov := intrinsics.overflow_add(dir.virtual_address, dir.size)
		if dir.virtual_address == 0 || ov {
			return .Invalid_Data_Directory
		}
	}

	return nil
}

detect_format :: proc(
	data: []u8,
	offset: int,
	size_of_optional_header: int,
) -> (
	fixed_size: int,
	groups: Field_Groups,
	err: pe.Error,
) {
	if pe.speculative_test(data, offset, format.IMAGE_OPTIONAL_HEADER_MAGIC_PE32) {
		fixed_size = PE32_FIXED_SIZE
		groups = pe32_groups
	} else if pe.speculative_test(data, offset, format.IMAGE_OPTIONAL_HEADER_MAGIC_PE64) {
		fixed_size = PE64_FIXED_SIZE
		groups = pe64_groups
	} else {
		return {}, {}, .Invalid_Magic
	}

	if size_of_optional_header < fixed_size {
		return {}, {}, .Truncated_Fixed_Fields
	}

	return
}

decode_optional_header :: proc(
	data: []u8,
	offset: int,
	size_of_optional_header: int,
) -> (
	header: pe.Optional_Header,
	err: pe.Error,
) {
	if size_of_optional_header < 2 {
		return {}, .Header_Too_Small
	}

	end, ov := intrinsics.overflow_add(offset, size_of_optional_header)
	if ov || end > len(data) {
		return {}, .Buffer_Overflow
	}

	fixed_size, groups := detect_format(data, offset, size_of_optional_header) or_return

	header = transpose_optional(data[offset:], groups)
	if e := validate_header(&header); e != nil {
		return {}, e
	}

	read_data_directories(&header, data[offset + fixed_size:offset + size_of_optional_header])
	if e := validate_data_directories(&header); e != nil {
		return {}, e
	}

	return
}
