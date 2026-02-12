package format

Image_Debug_Type :: enum u32le {
	Unknown       = 0,
	Coff          = 1,
	Codeview      = 2,
	Fpo           = 3,
	Misc          = 4,
	Exception     = 5,
	Fixup         = 6,
	Omap_To_Src   = 7,
	Omap_From_Src = 8,
	Borland       = 9,
	Reserved10    = 10,
}

Image_Debug_Directory :: struct #align (4) {
	characteristics:     u32le,
	time_date_stamp:     u32le,
	major_version:       u16le,
	minor_version:       u16le,
	type:                Image_Debug_Type,
	size_of_data:        u32le,
	address_of_raw_data: u32le,
	pointer_to_raw_data: u32le,
}
