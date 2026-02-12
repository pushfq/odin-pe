package format

IMAGE_ORDINAL_FLAG64 :: 0x8000000000000000
IMAGE_ORDINAL_FLAG32 :: 0x80000000

Image_Import_By_Name :: struct #packed {
	hint: u16le,
	name: [1]u8,
}

Image_Import_Descriptor :: struct #align (4) {
	u0:              struct #raw_union {
		characteristics:      u32le,
		original_first_thunk: u32le,
	},
	time_date_stamp: u32le,
	forwarder_chain: u32le,
	name:            u32le,
	first_thunk:     u32le,
}

Image_Thunk_Data64 :: struct #align (8) {
	u0: struct #raw_union {
		forwarder_string: u64le,
		function:         u64le,
		ordinal:          u64le,
		address_of_data:  u64le,
	},
}

Image_Thunk_Data32 :: struct #align (4) {
	u0: struct #raw_union {
		forwarder_string: u32le,
		function:         u32le,
		ordinal:          u32le,
		address_of_data:  u32le,
	},
}


image_ordinal64 :: #force_inline proc "contextless" (ordinal: u64le) -> u64le {
	return ordinal & 0xffff
}

image_ordinal32 :: #force_inline proc "contextless" (ordinal: u32le) -> u32le {
	return ordinal & 0xffff
}

image_snap_by_ordinal64 :: #force_inline proc "contextless" (ordinal: u64le) -> bool {
	return (ordinal & IMAGE_ORDINAL_FLAG64) != 0
}

image_snap_by_ordinal32 :: #force_inline proc "contextless" (ordinal: u32le) -> bool {
	return (ordinal & IMAGE_ORDINAL_FLAG32) != 0
}

image_ordinal :: proc {
	image_ordinal32,
	image_ordinal64,
}

image_snap_by_ordinal :: proc {
	image_snap_by_ordinal32,
	image_snap_by_ordinal64,
}
