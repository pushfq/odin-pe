package format

Unwind_Flag :: enum {
	Ehandler  = 0,
	Uhandler  = 1,
	Chaininfo = 2,
}

Unwind_Flags :: distinct bit_set[Unwind_Flag;u8]

Exception_Disposition :: enum {
	Continue_Execution,
	Continue_Search,
	Nested_Exception,
	Collided_Unwind,
}

Unwind_Op_Code :: enum u8 {
	Push_Nonvol     = 0,
	Alloc_Large     = 1,
	Alloc_Small     = 2,
	Set_Fpreg       = 3,
	Save_Nonvol     = 4,
	Save_Nonvol_Far = 5,
	Epilog          = 6,
	Save_Xmm128     = 8,
	Save_Xmm128_Far = 9,
	Push_Machframe  = 10,
}

Unwind_Code :: struct #raw_union {
	u0:           bit_field u16le {
		code_offset: u8             | 8,
		unwind_op:   Unwind_Op_Code | 4,
		op_info:     u8             | 4,
	},
	frame_offset: u16le,
}

Unwind_Info :: struct #packed {
	u0:             bit_field u8 {
		version: u8 | 3,
		flags:   u8 | 5,
	},
	size_of_prolog: u8,
	count_of_codes: u8,
	u1:             bit_field u8 {
		frame_register: u8 | 4,
		frame_offset:   u8 | 4,
	},
	unwind_code:    [1]Unwind_Code,
}

Runtime_Function :: struct #align (4) {
	begin_address: u32le,
	end_address:   u32le,
	u0:            struct #raw_union {
		unwind_info_address: u32le,
		unwind_data:         u32le,
	},
}
