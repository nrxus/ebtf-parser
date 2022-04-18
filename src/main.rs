use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};

use btf_sys::{
    btf_array, btf_enum, btf_header, btf_member, btf_param, btf_type, BTF_INT_BOOL, BTF_INT_CHAR,
    BTF_INT_SIGNED, BTF_KIND_ARRAY, BTF_KIND_CONST, BTF_KIND_ENUM, BTF_KIND_FLOAT, BTF_KIND_FUNC,
    BTF_KIND_FUNC_PROTO, BTF_KIND_FWD, BTF_KIND_INT, BTF_KIND_PTR, BTF_KIND_RESTRICT,
    BTF_KIND_STRUCT, BTF_KIND_TYPEDEF, BTF_KIND_UNION, BTF_KIND_VOLATILE,
};

fn info_kind(ty: &btf_type) -> u32 {
    (ty.info >> 24) & 0x1f
}

fn info_vlen(ty: &btf_type) -> u16 {
    (ty.info & 0xFFFF) as u16
}

fn info_kind_flag(ty: &btf_type) -> bool {
    ty.info >> 31 == 1
}

#[derive(Debug)]
enum BtfType {
    Int {
        name: String,
        size: u32,
        encoding: IntEncoding,
        bits: u8,
        offset: u8,
    },
    Pointer {
        ty: u32,
    },
    Array {
        ty: u32,
        index_type: u32,
        nelems: u32,
    },
    Struct {
        name: Option<String>,
        size: u32,
        members: Vec<Member>,
    },
    Union {
        name: Option<String>,
        size: u32,
        members: Vec<Member>,
    },
    Enum {
        name: Option<String>,
        variants: Vec<EnumVariant>,
        // according to btf documentation this should always be 4, but
        // in practice it is sometimes 1 (packed enums) or 8 (large
        // enums).
        size: u8,
    },
    Fwd {
        name: String,
        kind: FwdKind,
    },
    TypeDef {
        name: String,
        ty: u32,
    },
    Volatile {
        ty: u32,
    },
    Const {
        ty: u32,
    },
    Restrict {
        ty: u32,
    },
    Func {
        name: String,
        ty: u32,
    },
    FuncProto {
        params: Vec<FuncProtoParam>,
        return_ty: u32,
        has_varargs: bool,
    },
    // Var {},
    // DataSec {},
    Float {
        name: String,
        size: u8,
    },
    // DeclTag {},
    // TypeTag {},
}

#[derive(Debug)]
struct EnumVariant {
    name: String,
    val: i32,
}

#[derive(Debug)]
struct FuncProtoParam {
    name: Option<String>,
    ty: u32,
}

#[derive(Debug)]
enum FwdKind {
    Struct,
    Union,
}

#[derive(Debug)]
struct Member {
    // per the docs this should be a valid identifier, however in
    // practice some struct/union members can be anonymous in that
    // they do not contain a name so we are making it optional to
    // account for that
    name: Option<String>,
    ty: u32,
    offset: u32,
    bitfield_size: Option<u8>,
}

impl Member {
    pub fn read_from(
        data: &mut &[u8],
        strings: &StringsTable,
        kind_flag: bool,
    ) -> Result<Self, ()> {
        let member: btf_member = read(data)?;
        let (offset, bitfield_size) = if kind_flag {
            let offset = member.offset & 0xFFFFFF;
            let bitfield_size = member.offset >> 24;
            (offset, Some(bitfield_size as u8).filter(|s| *s != 0))
        } else {
            (member.offset & 0xFFFFFF, None)
        };

        Ok(Member {
            name: strings.optional_name(member.name_off as usize),
            ty: member.type_,
            offset,
            bitfield_size,
        })
    }
}

#[derive(Debug)]
enum IntEncoding {
    None,
    Signed,
    Char,
    Bool,
}

impl BtfType {
    pub fn read_from(data: &mut &[u8], strings: &StringsTable) -> Result<BtfType, ()> {
        let ty: btf_type = read(data)?;
        let name_offset = ty.name_off as usize;
        let info_vlen = info_vlen(&ty);
        let info_kind_flag = info_kind_flag(&ty);

        match info_kind(&ty) {
            BTF_KIND_INT => {
                assert!(info_vlen == 0);
                assert!(!info_kind_flag);

                let size = unsafe { ty.__bindgen_anon_1.size };
                let int_data: u32 = read(data).unwrap();

                let encoding = match (int_data >> 24) & 0x0F {
                    BTF_INT_SIGNED => IntEncoding::Signed,
                    BTF_INT_CHAR => IntEncoding::Char,
                    BTF_INT_BOOL => IntEncoding::Bool,
                    _ => IntEncoding::None,
                };

                let bits = (int_data & 0xFF) as u8;
                assert!(size * 8 >= bits as u32);

                let offset = (int_data >> 16 & 0xFF) as u8;

                Ok(BtfType::Int {
                    name: strings.name(name_offset),
                    size,
                    encoding,
                    bits,
                    offset,
                })
            }
            BTF_KIND_PTR => {
                assert!(name_offset == 0);
                assert!(!info_kind_flag);
                assert!(info_vlen == 0);

                Ok(BtfType::Pointer {
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                })
            }
            BTF_KIND_ARRAY => {
                assert!(name_offset == 0);
                assert!(!info_kind_flag);
                assert!(info_vlen == 0);

                let data: btf_array = read(data).unwrap();

                Ok(BtfType::Array {
                    index_type: data.index_type,
                    nelems: data.nelems,
                    ty: data.type_,
                })
            }
            BTF_KIND_STRUCT => {
                let members: Vec<_> = (0..info_vlen)
                    .map(|_| Member::read_from(data, strings, info_kind_flag).unwrap())
                    .collect();

                Ok(BtfType::Struct {
                    name: strings.optional_name(name_offset),
                    size: unsafe { ty.__bindgen_anon_1.size },
                    members,
                })
            }
            BTF_KIND_UNION => {
                let members: Vec<_> = (0..info_vlen)
                    .map(|_| Member::read_from(data, strings, info_kind_flag).unwrap())
                    .collect();

                Ok(BtfType::Union {
                    name: strings.optional_name(name_offset),
                    size: unsafe { ty.__bindgen_anon_1.size },
                    members,
                })
            }
            BTF_KIND_ENUM => {
                assert!(!info_kind_flag);

                let variants = (0..info_vlen)
                    .map(|_| {
                        let variant: btf_enum = read(data).unwrap();
                        EnumVariant {
                            name: strings.name(variant.name_off as usize),
                            val: variant.val,
                        }
                    })
                    .collect();

                Ok(BtfType::Enum {
                    name: strings.optional_name(name_offset),
                    variants,
                    size: unsafe { ty.__bindgen_anon_1.size } as u8,
                })
            }
            BTF_KIND_FWD => {
                assert!(info_vlen == 0);
                assert!(unsafe { ty.__bindgen_anon_1.type_ } == 0);

                Ok(BtfType::Fwd {
                    name: strings.name(name_offset),
                    kind: if info_kind_flag {
                        FwdKind::Union
                    } else {
                        FwdKind::Struct
                    },
                })
            }
            BTF_KIND_TYPEDEF => {
                assert!(!info_kind_flag);
                assert!(info_vlen == 0);

                Ok(BtfType::TypeDef {
                    name: strings.name(name_offset),
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                })
            }
            BTF_KIND_VOLATILE => {
                assert!(name_offset == 0);
                assert!(!info_kind_flag);
                assert!(info_vlen == 0);

                Ok(BtfType::Volatile {
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                })
            }
            BTF_KIND_CONST => {
                assert!(name_offset == 0);
                assert!(!info_kind_flag);
                assert!(info_vlen == 0);

                Ok(BtfType::Const {
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                })
            }
            BTF_KIND_RESTRICT => {
                assert!(name_offset == 0);
                assert!(!info_kind_flag);
                assert!(info_vlen == 0);

                Ok(BtfType::Const {
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                })
            }
            BTF_KIND_FUNC => {
                assert!(!info_kind_flag);
                assert!(info_vlen == 0);

                Ok(BtfType::Func {
                    name: strings.name(name_offset),
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                })
            }
            BTF_KIND_FUNC_PROTO => {
                assert!(name_offset == 0);
                assert!(!info_kind_flag);

                let params: Vec<_> = (0..info_vlen)
                    .filter_map(|_| {
                        let param: btf_param = read(data).unwrap();
                        let name = strings.optional_name(param.name_off as usize);

                        if param.type_ == 0 && name.is_none() {
                            None
                        } else {
                            Some(FuncProtoParam {
                                name,
                                ty: param.type_,
                            })
                        }
                    })
                    .collect();

                let has_varargs = match (info_vlen as usize) - params.len() {
                    0 => false,
                    1 => true,
                    _ => panic!("unexpected func proto names"),
                };

                Ok(BtfType::FuncProto {
                    return_ty: unsafe { ty.__bindgen_anon_1.type_ },
                    has_varargs,
                    params,
                })
            }
            // BTF_KIND_VAR => {},
            // BTF_KIND_DATASEC => {},
            BTF_KIND_FLOAT => {
                assert!(!info_kind_flag);
                assert_eq!(info_vlen, 0);

                let size = unsafe { ty.__bindgen_anon_1.size };
                assert!(size == 2 || size == 4 || size == 8 || size == 12 || size == 16);

                Ok(BtfType::Float {
                    name: strings.name(name_offset),
                    size: size as u8,
                })
            }
            // BTF_KIND_DECL_TAG => {},
            // BTF_KIND_TYPE_TAG => {},
            k => panic!("unhandled kind: {k}"),
        }
    }
}

fn read<T: Copy>(data: &mut &[u8]) -> Result<T, ()> {
    if data.len() < std::mem::size_of::<T>() {
        return Err(());
    }

    let value = unsafe { std::ptr::read((*data).as_ptr() as *const T) };
    *data = &data[std::mem::size_of::<T>()..];

    Ok(value)
}

fn main() {
    let file = File::open("/sys/kernel/btf/vmlinux").unwrap();

    let RawBtf { types, strings, .. } = RawBtf::read(file);

    let mut data: &[u8] = &types;

    while let Ok(ty) = BtfType::read_from(&mut data, &strings) {
        dbg!(&ty);
    }
}

struct RawBtf {
    header: btf_header,
    types: Vec<u8>,
    strings: StringsTable,
}

struct StringsTable(Vec<u8>);

impl StringsTable {
    pub fn optional_name(&self, offset: usize) -> Option<String> {
        if offset == 0 {
            None
        } else {
            Some(self.name(offset))
        }
    }

    pub fn name(&self, offset: usize) -> String {
        assert!(offset != 0);
        assert!((offset as usize) < self.0.len());

        let name: Vec<_> = self.0[offset..]
            .iter()
            .copied()
            .take_while(|&b| b != 0_u8)
            .collect();

        String::from_utf8(name).unwrap()
    }
}

impl RawBtf {
    pub fn read(mut file: File) -> Self {
        let header = read_header(&mut file);

        let mut types: Vec<u8> = vec![0; header.type_len as usize];
        let mut strings: Vec<u8> = vec![0; header.str_len as usize];

        if header.type_off < header.str_off {
            file.seek(SeekFrom::Current(header.type_off as i64))
                .unwrap();
            file.read_exact(&mut types).unwrap();

            file.seek(SeekFrom::Current((header.str_off - header.type_len) as i64))
                .unwrap();
            file.read_exact(&mut strings).unwrap();
        } else {
            file.seek(SeekFrom::Current(header.str_off as i64)).unwrap();
            file.read_exact(&mut strings).unwrap();

            file.seek(SeekFrom::Current((header.type_off - header.str_len) as i64))
                .unwrap();
            file.read_exact(&mut types).unwrap();
        };

        RawBtf {
            header,
            types,
            strings: StringsTable(strings),
        }
    }
}

const MAGIC: u16 = 0xEB9F;

fn read_header(mut buffer: impl Read + Seek) -> btf_header {
    let header: btf_header = unsafe {
        let mut header = [0_u8; std::mem::size_of::<btf_header>()];
        buffer.read_exact(&mut header).unwrap();
        std::mem::transmute(header)
    };

    if header.magic != MAGIC {
        panic!("the parsed vmlinux does not match machine's endian-ness");
    }

    let offset: i64 = header.hdr_len as i64 - std::mem::size_of::<btf_header>() as i64;

    // skip the header fields we do not know about
    buffer.seek(SeekFrom::Current(offset)).unwrap();

    header
}
