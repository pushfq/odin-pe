package format

Win_Certificate_Revision :: enum u16le {
	Revision_1_0 = 0x0100,
	Revision_2_0 = 0x0200,
}

Win_Certificate_Type :: enum u16le {
	X509             = 1,
	Pkcs_Signed_Data = 2,
	Reserved_1       = 3,
	Pkcs1_Sign       = 9,
}

Win_Certificate :: struct #align (4) {
	length:           u32le,
	revision:         Win_Certificate_Revision,
	certificate_type: Win_Certificate_Type,
	certificate:      [1]u8,
}
