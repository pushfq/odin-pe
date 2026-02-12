package format

Image_Export_Directory :: struct #align (4) {
	characteristics:          u32le,
	time_date_stamp:          u32le,
	major_version:            u16le,
	minor_version:            u16le,
	name:                     u32le,
	base:                     u32le,
	number_of_functions:      u32le,
	number_of_names:          u32le,
	address_of_functions:     u32le,
	address_of_names:         u32le,
	address_of_name_ordinals: u32le,
}
