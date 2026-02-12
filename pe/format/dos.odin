package format

IMAGE_DOS_SIGNATURE :: u16le(0x5A4D)
IMAGE_NT_SIGNATURE :: u32le(0x00004550)

Image_DOS_Header :: struct #align (2) {
	e_magic:    u16le,
	e_cblp:     u16le,
	e_cp:       u16le,
	e_crlc:     u16le,
	e_cparhdr:  u16le,
	e_minalloc: u16le,
	e_maxalloc: u16le,
	e_ss:       u16le,
	e_sp:       u16le,
	e_csum:     u16le,
	e_ip:       u16le,
	e_cs:       u16le,
	e_lfarlc:   u16le,
	e_ovno:     u16le,
	e_res:      [4]u16le,
	e_oemid:    u16le,
	e_oeminfo:  u16le,
	e_res2:     [10]u16le,
	e_lfanew:   i32le,
}
