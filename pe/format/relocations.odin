package format

Image_Based_Relocation_Type :: enum u16le {
	Absolute       = 0,
	High           = 1,
	Low            = 2,
	Highlow        = 3,
	Highadj        = 4,
	Mips_Jmpaddr   = 5,
	Mips_Jmpaddr16 = 9,
	Ia64_Imm64     = 9,
	Dir64          = 10,
}

Image_Base_Relocation :: struct #align (4) {
	virtual_address: u32le,
	size_of_block:   u32le,
}

Base_Relocation_Entry :: struct {
	type:            Image_Based_Relocation_Type,
	virtual_address: u64,
}
