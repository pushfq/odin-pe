package format

Image_File_Machine :: enum u16le {
	Unknown    = 0x0000,
	Targethost = 0x0001,
	I386       = 0x014c,
	R3000      = 0x0162,
	R4000      = 0x0166,
	R10000     = 0x0168,
	Wcemipsv2  = 0x0169,
	Alpha      = 0x0184,
	Sh3        = 0x01a2,
	Sh3dsp     = 0x01a3,
	Sh3e       = 0x01a4,
	Sh4        = 0x01a6,
	Sh5        = 0x01a8,
	Arm        = 0x01c0,
	Thumb      = 0x01c2,
	Armnt      = 0x01c4,
	Am33       = 0x01d3,
	Powerpc    = 0x01f0,
	Powerpcfp  = 0x01f1,
	Ia64       = 0x0200,
	Mips16     = 0x0266,
	Alpha64    = 0x0284,
	Mipsfpu    = 0x0366,
	Mipsfpu16  = 0x0466,
	Axp64      = 0x0284,
	Tricore    = 0x0520,
	Cef        = 0x0CEF,
	Ebc        = 0x0EBC,
	Amd64      = 0x8664,
	M32r       = 0x9041,
	Arm64      = 0xAA64,
	Cee        = 0xC0EE,
}

Image_File_Characteristic :: enum u16le {
	Relocs_Stripped         = 0,
	Executable_Image        = 1,
	Line_Nums_Stripped      = 2,
	Local_Syms_Stripped     = 3,
	Aggresive_Ws_Trim       = 4,
	Large_Address_Aware     = 5,
	Bytes_Reversed_Lo       = 7,
	Machine_32Bit           = 8,
	Debug_Stripped          = 9,
	Removable_Run_From_Swap = 10,
	Net_Run_From_Swap       = 11,
	System                  = 12,
	Dll                     = 13,
	Up_System_Only          = 14,
	Bytes_Reversed_Hi       = 15,
}

Image_File_Characteristics :: distinct bit_set[Image_File_Characteristic;u16le]

Image_File_Header :: struct #align (4) {
	machine:                 Image_File_Machine,
	number_of_sections:      u16le,
	time_date_stamp:         u32le,
	pointer_to_symbol_table: u32le,
	number_of_symbols:       u32le,
	size_of_optional_header: u16le,
	characteristics:         Image_File_Characteristics,
}

IMAGE_OPTIONAL_HEADER_MAGIC_PE32 :: u16le(0x10B)
IMAGE_OPTIONAL_HEADER_MAGIC_PE64 :: u16le(0x20B)
IMAGE_OPTIONAL_HEADER_MAGIC_ROM :: u16le(0x107)

MIN_FILE_ALIGNMENT :: 512
MAX_FILE_ALIGNMENT :: 65536

Image_Data_Directory :: struct #align (4) {
	virtual_address: u32le,
	size:            u32le,
}

Image_Data_Directories :: enum {
	Export         = 0,
	Import         = 1,
	Resource       = 2,
	Exception      = 3,
	Security       = 4,
	Basereloc      = 5,
	Debug          = 6,
	Architecture   = 7,
	Globalptr      = 8,
	Tls            = 9,
	Load_Config    = 10,
	Bound_Import   = 11,
	Iat            = 12,
	Delay_Import   = 13,
	Com_Descriptor = 14,
	Reserved       = 15,
}

Image_Subsystem :: enum u16le {
	Unknown                  = 0,
	Native                   = 1,
	Windows_Gui              = 2,
	Windows_Cui              = 3,
	Os2_Cui                  = 5,
	Posix_Cui                = 7,
	Native_Windows           = 8,
	Windows_Ce_Gui           = 9,
	Efi_Application          = 10,
	Efi_Boot_Service_Driver  = 11,
	Efi_Runtime_Driver       = 12,
	Efi_Rom                  = 13,
	Xbox                     = 14,
	Windows_Boot_Application = 16,
}

Image_DLL_Characteristic :: enum {
	HighEntropyVa       = 5,
	DynamicBase         = 6,
	ForceIntegrity      = 7,
	NxCompat            = 8,
	NoIsolation         = 9,
	NoSeh               = 10,
	NoBind              = 11,
	Appcontainer        = 12,
	WdmDriver           = 13,
	GuardCf             = 14,
	TerminalServerAware = 15,
}

Image_DLL_Characteristics :: distinct bit_set[Image_DLL_Characteristic;u16le]
Image_CPR_Mask :: distinct [4]u32le

Image_ROM_Optional_Header :: struct #align (4) {
	magic:                      u16le,
	major_linker_version:       u8,
	minor_linker_version:       u8,
	size_of_code:               u32le,
	size_of_initialized_data:   u32le,
	size_of_uninitialized_data: u32le,
	address_of_entry_point:     u32le,
	base_of_code:               u32le,
	base_of_data:               u32le,
	base_of_bss:                u32le,
	gpr_mask:                   u32le,
	cpr_mask:                   Image_CPR_Mask,
	gp_value:                   u32le,
}

Image_Optional_Header32 :: struct #align (4) {
	magic:                          u16le,
	major_linker_version:           u8,
	minor_linker_version:           u8,
	size_of_code:                   u32le,
	size_of_initialized_data:       u32le,
	size_of_uninitialized_data:     u32le,
	address_of_entry_point:         u32le,
	base_of_code:                   u32le,
	base_of_data:                   u32le,
	image_base:                     u32le,
	section_alignment:              u32le,
	file_alignment:                 u32le,
	major_operating_system_version: u16le,
	minor_operating_system_version: u16le,
	major_image_version:            u16le,
	minor_image_version:            u16le,
	major_subsystem_version:        u16le,
	minor_subsystem_version:        u16le,
	win32_version_value:            u32le,
	size_of_image:                  u32le,
	size_of_headers:                u32le,
	check_sum:                      u32le,
	subsystem:                      Image_Subsystem,
	dll_characteristics:            Image_DLL_Characteristics,
	size_of_stack_reserve:          u32le,
	size_of_stack_commit:           u32le,
	size_of_heap_reserve:           u32le,
	size_of_heap_commit:            u32le,
	loader_flags:                   u32le,
	number_of_rva_and_sizes:        u32le,
	data_directory:                 [Image_Data_Directories]Image_Data_Directory,
}

Image_Optional_Header64 :: struct #align (4) {
	magic:                          u16le,
	major_linker_version:           u8,
	minor_linker_version:           u8,
	size_of_code:                   u32le,
	size_of_initialized_data:       u32le,
	size_of_uninitialized_data:     u32le,
	address_of_entry_point:         u32le,
	base_of_code:                   u32le,
	image_base:                     u64le,
	section_alignment:              u32le,
	file_alignment:                 u32le,
	major_operating_system_version: u16le,
	minor_operating_system_version: u16le,
	major_image_version:            u16le,
	minor_image_version:            u16le,
	major_subsystem_version:        u16le,
	minor_subsystem_version:        u16le,
	win32_version_value:            u32le,
	size_of_image:                  u32le,
	size_of_headers:                u32le,
	check_sum:                      u32le,
	subsystem:                      Image_Subsystem,
	dll_characteristics:            Image_DLL_Characteristics,
	size_of_stack_reserve:          u64le,
	size_of_stack_commit:           u64le,
	size_of_heap_reserve:           u64le,
	size_of_heap_commit:            u64le,
	loader_flags:                   u32le,
	number_of_rva_and_sizes:        u32le,
	data_directory:                 [Image_Data_Directories]Image_Data_Directory,
}

Image_Storage_Class :: enum u8 {
	End_Of_Function  = 0xFF,
	Null             = 0,
	Automatic        = 1,
	External         = 2,
	Static           = 3,
	Register         = 4,
	External_Def     = 5,
	Label            = 6,
	Undefined_Label  = 7,
	Member_Of_Struct = 8,
	Argument         = 9,
	Struct_Tag       = 10,
	Member_Of_Union  = 11,
	Union_Tag        = 12,
	Type_Definition  = 13,
	Undefined_Static = 14,
	Enum_Tag         = 15,
	Member_Of_Enum   = 16,
	Register_Param   = 17,
	Bit_Field        = 18,
	Block            = 100,
	Function         = 101,
	End_Of_Struct    = 102,
	File             = 103,
	Section          = 104,
	Weak_External    = 105,
	Clr_Token        = 107,
}

Image_Symbol :: struct #align (4) {
	u0:                    struct #raw_union {
		name:       struct {
			short: u32le,
			long:  u32le,
		},
		short_name: [8]u8,
		long_name:  [2]u32le,
	},
	value:                 u32le,
	section_number:        i16le,
	type:                  u16le,
	storage_class:         Image_Storage_Class,
	number_of_aux_symbols: u8,
}


is_dll :: proc "contextless" (characteristics: Image_File_Characteristics) -> bool {
	return .Dll in characteristics
}

is_executable :: proc "contextless" (characteristics: Image_File_Characteristics) -> bool {
	return .Executable_Image in characteristics
}

is_large_address_aware :: proc "contextless" (
	characteristics: Image_File_Characteristics,
) -> bool {
	return .Large_Address_Aware in characteristics
}

is_machine_64bit :: proc "contextless" (machine: Image_File_Machine) -> bool {
	#partial switch machine {
	case .Amd64, .Arm64, .Ia64, .Alpha64:
		return true
	}
	return false
}
