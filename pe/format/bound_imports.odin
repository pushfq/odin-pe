package format

Image_Bound_Import_Descriptor :: struct #align (4) {
	time_date_stamp:                 u32le,
	offset_module_name:              u16le,
	number_of_module_forwarder_refs: u16le,
}

Image_Bound_Forwarder_Ref :: struct #align (4) {
	time_date_stamp:    u32le,
	offset_module_name: u16le,
	reserved:           u16le,
}
