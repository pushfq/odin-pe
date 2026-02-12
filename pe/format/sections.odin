package format

import "core:bytes"

IMAGE_SECTION_ALIGN_MASK :: Image_Section_Characteristics(0x00F00000)

Image_Section_Flag :: enum {
	Type_No_Pad                 = 3,
	Contains_Code               = 5,
	Contains_Initialized_Data   = 6,
	Contains_Uninitialized_Data = 7,
	Link_Other                  = 8,
	Link_Info                   = 9,
	Link_Remove                 = 11,
	Link_Comdat                 = 12,
	No_Defer_Spec_Exc           = 14,
	Gprel                       = 15,
	Mem_Purgeable               = 17,
	Mem_Locked                  = 18,
	Mem_Preload                 = 19,
	Link_Nreloc_Ovfl            = 24,
	Mem_Discardable             = 25,
	Mem_Not_Cached              = 26,
	Mem_Not_Paged               = 27,
	Mem_Shared                  = 28,
	Mem_Execute                 = 29,
	Mem_Read                    = 30,
	Mem_Write                   = 31,
}

Image_Section_Align :: enum Image_Section_Characteristics {
	Align_1Bytes    = 0x00100000,
	Align_2Bytes    = 0x00200000,
	Align_4Bytes    = 0x00300000,
	Align_8Bytes    = 0x00400000,
	Align_16Bytes   = 0x00500000,
	Align_32Bytes   = 0x00600000,
	Align_64Bytes   = 0x00700000,
	Align_128Bytes  = 0x00800000,
	Align_256Bytes  = 0x00900000,
	Align_512Bytes  = 0x00A00000,
	Align_1024Bytes = 0x00B00000,
	Align_2048Bytes = 0x00C00000,
	Align_4096Bytes = 0x00D00000,
	Align_8192Bytes = 0x00E00000,
}

Image_Section_Characteristics :: distinct u32le
Image_Section_Flags :: distinct bit_set[Image_Section_Flag;Image_Section_Characteristics]

Image_Section_Header :: struct #align (4) {
	name:                   [8]u8,
	virtual_size:           u32le,
	virtual_address:        u32le,
	size_of_raw_data:       u32le,
	pointer_to_raw_data:    u32le,
	pointer_to_relocations: u32le,
	pointer_to_linenumbers: u32le,
	number_of_relocations:  u16le,
	number_of_linenumbers:  u16le,
	characteristics:        Image_Section_Characteristics,
}

DEFAULT_SECTION_ALIGNMENT :: 16


name_of_section :: proc(h: ^Image_Section_Header) -> string {
	n := bytes.index_byte(h.name[:], 0)
	if n < 0 {
		n = len(h.name)
	}
	return string(h.name[:n])
}

alignment_for_characteristics :: proc(ch: Image_Section_Characteristics) -> int {
	if bits := ch & IMAGE_SECTION_ALIGN_MASK; bits != 0 {
		return 1 << ((bits >> 20) - 1)
	}
	return DEFAULT_SECTION_ALIGNMENT
}

section_flags :: proc(ch: Image_Section_Characteristics) -> Image_Section_Flags {
	return transmute(Image_Section_Flags)(ch & ~IMAGE_SECTION_ALIGN_MASK)
}

section_has_all :: proc(h: ^Image_Section_Header, want: Image_Section_Flags) -> bool {
	have := section_flags(h.characteristics)
	return (have & want) == want
}

section_has_any :: proc(h: ^Image_Section_Header, want: Image_Section_Flags) -> bool {
	have := section_flags(h.characteristics)
	return (have & want) != {}
}


section_is_executable :: proc(h: ^Image_Section_Header) -> bool {
	return section_has_all(h, {.Mem_Execute})
}

section_is_readable :: proc(h: ^Image_Section_Header) -> bool {
	return section_has_all(h, {.Mem_Read})
}

section_is_writable :: proc(h: ^Image_Section_Header) -> bool {
	return section_has_all(h, {.Mem_Write})
}

section_contains_code :: proc(h: ^Image_Section_Header) -> bool {
	return section_has_all(h, {.Contains_Code})
}

section_contains_initialized_data :: proc(h: ^Image_Section_Header) -> bool {
	return section_has_all(h, {.Contains_Initialized_Data})
}

section_contains_uninitialized_data :: proc(h: ^Image_Section_Header) -> bool {
	return section_has_all(h, {.Contains_Uninitialized_Data})
}


effective_section_size :: proc "contextless" (h: ^Image_Section_Header) -> u32le {
	if h.virtual_size != 0 {
		return h.virtual_size
	}
	return h.size_of_raw_data
}

section_contains_rva :: proc "contextless" (h: ^Image_Section_Header, rva: u32le) -> bool {
	return rva >= h.virtual_address && rva < h.virtual_address + effective_section_size(h)
}

section_contains_offset :: proc "contextless" (h: ^Image_Section_Header, offset: u32le) -> bool {
	return offset >= h.pointer_to_raw_data && offset < h.pointer_to_raw_data + h.size_of_raw_data
}


rva_to_section :: proc(
	sections: []Image_Section_Header,
	rva: u32le,
) -> (
	result: ^Image_Section_Header,
	ok: bool,
) {
	for &section in sections {
		if section_contains_rva(&section, rva) {
			return &section, true
		}
	}
	return nil, false
}

rva_to_file_offset :: proc(
	sections: []Image_Section_Header,
	rva: u32le,
) -> (
	offset: u32le,
	ok: bool,
) {
	section := rva_to_section(sections, rva) or_return
	return rva - section.virtual_address + section.pointer_to_raw_data, true
}

file_offset_to_rva :: proc(
	sections: []Image_Section_Header,
	offset: u32le,
) -> (
	rva: u32le,
	ok: bool,
) {
	for &section in sections {
		if section_contains_offset(&section, offset) {
			return offset - section.pointer_to_raw_data + section.virtual_address, true
		}
	}
	return 0, false
}
