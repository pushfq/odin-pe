package format

Image_TLS_Directory64 :: struct #align (4) {
	start_address_of_raw_data: u64le,
	end_address_of_raw_data:   u64le,
	address_of_index:          u64le,
	address_of_callbacks:      u64le,
	size_of_zero_fill:         u32le,
	characteristics:           u32le,
}

Image_TLS_Directory32 :: struct #align (4) {
	start_address_of_raw_data: u32le,
	end_address_of_raw_data:   u32le,
	address_of_index:          u32le,
	address_of_callbacks:      u32le,
	size_of_zero_fill:         u32le,
	characteristics:           u32le,
}
