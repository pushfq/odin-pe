package format

Image_Delay_Import_Descriptor :: struct #align (4) {
	attrs:      u32le,
	dll_name:   u32le,
	hmod:       u32le,
	iat:        u32le,
	int_:       u32le,
	bound_iat:  u32le,
	unload_iat: u32le,
	time_stamp: u32le,
}
