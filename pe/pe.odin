package pe

import "./format"

Decode_Error :: enum {
	Header_Too_Small,
	Invalid_Magic,
	Truncated_Fixed_Fields,
	Buffer_Overflow,
	Invalid_Header,
	Invalid_Data_Directory,
}

Error :: union {
	Decode_Error,
}

Optional_Header :: struct {
	magic:                          u16,
	major_linker_version:           u8,
	minor_linker_version:           u8,
	image_base:                     u64,
	size_of_stack_reserve:          u64,
	size_of_stack_commit:           u64,
	size_of_heap_reserve:           u64,
	size_of_heap_commit:            u64,
	address_of_entry_point:         u32,
	size_of_code:                   u32,
	size_of_initialized_data:       u32,
	size_of_uninitialized_data:     u32,
	base_of_code:                   u32,
	base_of_data:                   u32,
	section_alignment:              u32,
	file_alignment:                 u32,
	size_of_image:                  u32,
	size_of_headers:                u32,
	check_sum:                      u32,
	win32_version_value:            u32,
	loader_flags:                   u32,
	number_of_rva_and_sizes:        u32,
	major_operating_system_version: u16,
	minor_operating_system_version: u16,
	major_image_version:            u16,
	minor_image_version:            u16,
	major_subsystem_version:        u16,
	minor_subsystem_version:        u16,
	subsystem:                      format.Image_Subsystem,
	dll_characteristics:            format.Image_DLL_Characteristics,
	data_directories:               [format.Image_Data_Directories]format.Image_Data_Directory,
}

get_data_directory :: proc(
	h: ^Optional_Header,
	dir: format.Image_Data_Directories,
) -> (
	format.Image_Data_Directory,
	bool,
) {
	entry := h.data_directories[dir]
	return entry, entry.size != 0 && entry.virtual_address != 0
}
