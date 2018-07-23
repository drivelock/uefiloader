static UINT8 shim_cert[] = {
0x30, 0x82, 0x05, 0x8c, 0x30, 0x82, 0x04, 0x74, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x02, 0xaa, 0xa7, 0x6b, 0xdc, 0x94, 0xd3, 0x50, 0xea, 0xf8, 0x47, 0x96, 0x30, 0x28, 0xee, 0xc5, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x6c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0c, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x10, 0x77, 0x77, 0x77, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x2b, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x22, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x45, 0x56, 0x20, 0x43, 0x6f, 0x64, 0x65, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x43, 0x41, 0x20, 0x28, 0x53, 0x48, 0x41, 0x32, 0x29, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x38, 0x30, 0x34, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x31, 0x30, 0x34, 0x31, 0x34, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x81, 0xa8, 0x31, 0x13, 0x30, 0x11, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x03, 0x13, 0x02, 0x44, 0x45, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x0f, 0x0c, 0x14, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x20, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0a, 0x48, 0x52, 0x42, 0x20, 0x32, 0x33, 0x30, 0x32, 0x38, 0x38, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x44, 0x45, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x06, 0x42, 0x61, 0x79, 0x65, 0x72, 0x6e, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x08, 0x4d, 0xc3, 0xbc, 0x6e, 0x63, 0x68, 0x65, 0x6e, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0c, 0x44, 0x72, 0x69, 0x76, 0x65, 0x4c, 0x6f, 0x63, 0x6b, 0x20, 0x53, 0x45, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0c, 0x44, 0x72, 0x69, 0x76, 0x65, 0x4c, 0x6f, 0x63, 0x6b, 0x20, 0x53, 0x45, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb5, 0xbf, 0x1f, 0xab, 0x38, 0x04, 0xf9, 0x19, 0xab, 0x4d, 0x13, 0x25, 0xdb, 0x95, 0x59, 0x25, 0x17, 0xc6, 0x97, 0x8f, 0x91, 0xe3, 0x99, 0x5c, 0x99, 0x96, 0xde, 0x2e, 0x1a, 0x63, 0xf5, 0xef, 0xf6, 0x54, 0x69, 0xf3, 0xde, 0x99, 0x09, 0xc2, 0x18, 0xbc, 0xe4, 0xce, 0x7c, 0x74, 0x5f, 0x8b, 0x7c, 0xc7, 0xe7, 0xa7, 0xc4, 0x63, 0x4b, 0x1d, 0x3d, 0x3e, 0x92, 0xe4, 0x7e, 0xdf, 0x90, 0x87, 0x45, 0x6d, 0xcd, 0xec, 0x85, 0x7c, 0x5d, 0xb9, 0x3f, 0xd2, 0x34, 0x81, 0xf0, 0x12, 0x9f, 0x99, 0x77, 0x8e, 0xc0, 0x04, 0xe9, 0x49, 0x88, 0x84, 0x26, 0x26, 0x4c, 0xc2, 0x99, 0x39, 0x2f, 0x3c, 0xfc, 0x8b, 0x11, 0x2e, 0x6f, 0xcb, 0x2c, 0x2f, 0xbb, 0x31, 0x2c, 0x34, 0xc9, 0x5a, 0x28, 0x8a, 0x9c, 0x7f, 0x90, 0xef, 0x49, 0x7c, 0xb7, 0x97, 0x6c, 0x72, 0x78, 0xe9, 0x59, 0x11, 0xab, 0x7c, 0x53, 0x90, 0x54, 0x2e, 0xee, 0xc0, 0x80, 0xe4, 0xfa, 0xb6, 0x47, 0x95, 0x74, 0xd5, 0xb6, 0x73, 0x1a, 0x10, 0xa2, 0x4c, 0xc8, 0x76, 0x18, 0xc2, 0x1e, 0x90, 0x09, 0x9b, 0x51, 0x29, 0xdc, 0x51, 0x54, 0xee, 0x8d, 0xa5, 0xe2, 0xb3, 0x3f, 0x8f, 0xd4, 0xb4, 0xb3, 0x75, 0xbf, 0xef, 0xcd, 0x77, 0x8a, 0x4c, 0x68, 0xe8, 0x54, 0x20, 0x8a, 0x75, 0x9d, 0x32, 0x2b, 0x0e, 0xa8, 0xe1, 0x44, 0x9f, 0xcd, 0xa4, 0x58, 0x1e, 0xc7, 0xf0, 0xb0, 0x16, 0x3a, 0xe6, 0x79, 0xf8, 0xbf, 0x2f, 0x53, 0xbc, 0x17, 0xb1, 0x62, 0x55, 0x79, 0xbd, 0xd1, 0x59, 0x24, 0xe0, 0x70, 0x85, 0x9d, 0x3b, 0x6b, 0x38, 0x5d, 0x9f, 0x6d, 0x15, 0xd3, 0xd0, 0xc6, 0x3b, 0x57, 0x86, 0x74, 0x76, 0x8f, 0xb8, 0x8d, 0x19, 0xcc, 0x6e, 0xda, 0x21, 0x6f, 0xb2, 0xe3, 0x12, 0x73, 0x5b, 0xf5, 0x20, 0xfb, 0x39, 0xde, 0x61, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0xeb, 0x30, 0x82, 0x01, 0xe7, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x8f, 0xe8, 0x7e, 0xf0, 0x6d, 0x32, 0x6a, 0x00, 0x05, 0x23, 0xc7, 0x70, 0x97, 0x6a, 0x3a, 0x90, 0xff, 0x6b, 0xea, 0xd4, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xb1, 0x70, 0x68, 0xad, 0x43, 0x1b, 0x26, 0x5b, 0x36, 0x78, 0x37, 0xd8, 0xfa, 0xf1, 0x50, 0x50, 0xad, 0x84, 0x03, 0x3f, 0x30, 0x28, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x21, 0x30, 0x1f, 0xa0, 0x1d, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x08, 0x03, 0xa0, 0x11, 0x30, 0x0f, 0x0c, 0x0d, 0x44, 0x45, 0x2d, 0x48, 0x52, 0x42, 0x20, 0x32, 0x33, 0x30, 0x32, 0x38, 0x38, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03, 0x30, 0x7b, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x74, 0x30, 0x72, 0x30, 0x37, 0xa0, 0x35, 0xa0, 0x33, 0x86, 0x31, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x33, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x45, 0x56, 0x43, 0x6f, 0x64, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x53, 0x48, 0x41, 0x32, 0x2d, 0x67, 0x31, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x37, 0xa0, 0x35, 0xa0, 0x33, 0x86, 0x31, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x34, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x45, 0x56, 0x43, 0x6f, 0x64, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x53, 0x48, 0x41, 0x32, 0x2d, 0x67, 0x31, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x4b, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x44, 0x30, 0x42, 0x30, 0x37, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xfd, 0x6c, 0x03, 0x02, 0x30, 0x2a, 0x30, 0x28, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x1c, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x43, 0x50, 0x53, 0x30, 0x07, 0x06, 0x05, 0x67, 0x81, 0x0c, 0x01, 0x03, 0x30, 0x7e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x72, 0x30, 0x70, 0x30, 0x24, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x18, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x48, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x3c, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74, 0x73, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x45, 0x56, 0x43, 0x6f, 0x64, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x43, 0x41, 0x2d, 0x53, 0x48, 0x41, 0x32, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x89, 0x46, 0x07, 0x03, 0x9d, 0xc7, 0x7f, 0xc5, 0xb7, 0x9c, 0x4c, 0x56, 0x42, 0x0c, 0xf5, 0x29, 0x1e, 0x19, 0x48, 0x27, 0xd6, 0x0b, 0x86, 0xf0, 0x31, 0x38, 0x14, 0x46, 0x19, 0xe9, 0x00, 0x12, 0x37, 0x5d, 0x58, 0xcd, 0x48, 0xd0, 0xbc, 0xdc, 0x22, 0xb4, 0xf2, 0x6e, 0x19, 0x3b, 0xaf, 0x0c, 0xc3, 0xe1, 0x99, 0xd4, 0xf2, 0x5b, 0xc7, 0x47, 0xeb, 0x06, 0xe9, 0xd0, 0x96, 0x86, 0x82, 0x69, 0xc2, 0xd2, 0x53, 0xf4, 0xb7, 0x57, 0x58, 0xd2, 0xf3, 0x97, 0xdf, 0x4b, 0xe6, 0x47, 0xa2, 0x26, 0xfb, 0x48, 0xf5, 0xf6, 0xbe, 0x31, 0x61, 0xe9, 0x88, 0xd0, 0x93, 0xb2, 0x05, 0x79, 0x02, 0xed, 0xc7, 0x8d, 0x9d, 0x4f, 0x64, 0x3c, 0x21, 0x4e, 0x82, 0x9b, 0x11, 0x47, 0x10, 0x27, 0x04, 0xef, 0x9d, 0x49, 0x01, 0x3b, 0x63, 0x7e, 0x6b, 0xbb, 0x91, 0x79, 0xca, 0x45, 0xa7, 0x7a, 0xfb, 0xbd, 0xec, 0x89, 0x51, 0x00, 0x38, 0x20, 0x17, 0xd8, 0xc4, 0x28, 0x09, 0x23, 0xaa, 0x9b, 0x5a, 0x29, 0x76, 0x21, 0xd7, 0xbd, 0x2c, 0x4a, 0x6e, 0x87, 0x00, 0x97, 0x98, 0x64, 0x46, 0xfd, 0x45, 0xe2, 0xa9, 0xa8, 0xf0, 0xc7, 0x04, 0x03, 0x2b, 0xd5, 0x58, 0x66, 0x89, 0xa9, 0xc1, 0xfb, 0xb4, 0xd4, 0x0d, 0xe1, 0xce, 0x9a, 0x1d, 0xfb, 0xfd, 0x12, 0x39, 0x58, 0xed, 0x9b, 0x99, 0x5c, 0x76, 0x2f, 0x0a, 0x8b, 0xd9, 0x8a, 0x03, 0x28, 0xd6, 0x64, 0x63, 0x58, 0xa1, 0x4c, 0x82, 0x4e, 0x99, 0xe1, 0x00, 0xdc, 0x74, 0x7d, 0xf2, 0x4a, 0x78, 0xcd, 0x36, 0xf2, 0x8e, 0x9e, 0xdb, 0x82, 0x99, 0x17, 0x77, 0x43, 0x39, 0xa6, 0x3f, 0xf3, 0x5b, 0x85, 0xc9, 0x2a, 0x38, 0x9a, 0x5f, 0x9b, 0x19, 0xe4, 0x80, 0x69, 0x8e, 0x22, 0xd6, 0xc2, 0x4d, 0xeb, 0x76, 0x68, 0x43, 0xeb, 0x95, 0x37, 0x8c, 0x89
};