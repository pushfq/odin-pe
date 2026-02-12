package format

IMAGE_RESOURCE_NAME_IS_STRING :: 0x80000000
IMAGE_RESOURCE_DATA_IS_DIRECTORY :: 0x80000000

Image_Resource_Directory :: struct #align (4) {
	characteristics:         u32le,
	time_date_stamp:         u32le,
	major_version:           u16le,
	minor_version:           u16le,
	number_of_named_entries: u16le,
	number_of_id_entries:    u16le,
}

Image_Resource_Directory_Entry :: struct #align (4) {
	u0: struct #raw_union {
		name:       bit_field u32le {
			name_offset:    u32le | 31,
			name_is_string: u32le | 1,
		},
		name_dword: u32le,
		id:         u16le,
	},
	u1: struct #raw_union {
		offset_to_data: u32le,
		directory:      bit_field u32le {
			offset_to_directory: u32le | 31,
			data_is_directory:   u32le | 1,
		},
	},
}

Image_Resource_Data_Entry :: struct #align (4) {
	offset_to_data: u32le,
	size:           u32le,
	code_page:      u32le,
	reserved:       u32le,
}


resource_entry_is_directory :: #force_inline proc "contextless" (
	entry: ^Image_Resource_Directory_Entry,
) -> bool {
	return entry.u1.directory.data_is_directory != 0
}

resource_entry_is_named :: #force_inline proc "contextless" (
	entry: ^Image_Resource_Directory_Entry,
) -> bool {
	return entry.u0.name.name_is_string != 0
}

resource_entry_id :: #force_inline proc "contextless" (
	entry: ^Image_Resource_Directory_Entry,
) -> u16le {
	return entry.u0.id
}

resource_entry_name_offset :: #force_inline proc "contextless" (
	entry: ^Image_Resource_Directory_Entry,
) -> u32le {
	return entry.u0.name.name_offset
}

resource_entry_data_offset :: #force_inline proc "contextless" (
	entry: ^Image_Resource_Directory_Entry,
) -> u32le {
	return entry.u1.directory.offset_to_directory
}

resource_total_entries :: #force_inline proc "contextless" (
	dir: ^Image_Resource_Directory,
) -> int {
	return int(dir.number_of_named_entries) + int(dir.number_of_id_entries)
}
