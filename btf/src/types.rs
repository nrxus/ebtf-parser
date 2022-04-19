use btf_sys::{
    btf_array, btf_decl_tag, btf_enum, btf_member, btf_param, btf_type, btf_var, btf_var_secinfo,
    BTF_INT_BOOL, BTF_INT_CHAR, BTF_INT_SIGNED, BTF_KIND_ARRAY, BTF_KIND_CONST, BTF_KIND_DATASEC,
    BTF_KIND_DECL_TAG, BTF_KIND_ENUM, BTF_KIND_FLOAT, BTF_KIND_FUNC, BTF_KIND_FUNC_PROTO,
    BTF_KIND_FWD, BTF_KIND_INT, BTF_KIND_PTR, BTF_KIND_RESTRICT, BTF_KIND_STRUCT, BTF_KIND_TYPEDEF,
    BTF_KIND_UNION, BTF_KIND_VAR, BTF_KIND_VOLATILE,
};

use crate::StringsTable;

#[derive(Debug)]
pub enum BtfType {
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
    Var {
        name: String,
        ty: u32,
        // TODO: understand what this even means
        linkage: u32,
    },
    DataSec {
        name: String,
        size: u32,
        info: Vec<SecInfo>,
    },
    Float {
        name: String,
        size: u8,
    },
    DeclTag {
        name: String,
        ty: u32,
        component_idx: Option<u32>,
    },
    // TypeTag {},
}

impl BtfType {
    pub fn read_from(data: &mut &[u8], strings: &StringsTable) -> Result<BtfType, ()> {
        let ty: btf_type = read(data)?;
        let name_offset = ty.name_off as usize;
        let info_vlen = info_vlen(&ty);
        let info_kind_flag = info_kind_flag(&ty);

        match info_kind(&ty) {
            BTF_KIND_INT => {
                assert_eq!(info_vlen, 0);
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
                assert_eq!(name_offset, 0);
                assert!(!info_kind_flag);
                assert_eq!(info_vlen, 0);

                Ok(BtfType::Pointer {
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                })
            }
            BTF_KIND_ARRAY => {
                assert_eq!(name_offset, 0);
                assert!(!info_kind_flag);
                assert_eq!(info_vlen, 0);

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
                assert_eq!(info_vlen, 0);
                assert_eq!(unsafe { ty.__bindgen_anon_1.type_ }, 0);

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
                assert_eq!(info_vlen, 0);

                Ok(BtfType::TypeDef {
                    name: strings.name(name_offset),
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                })
            }
            BTF_KIND_VOLATILE => {
                assert_eq!(name_offset, 0);
                assert!(!info_kind_flag);
                assert_eq!(info_vlen, 0);

                Ok(BtfType::Volatile {
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                })
            }
            BTF_KIND_CONST => {
                assert_eq!(name_offset, 0);
                assert!(!info_kind_flag);
                assert_eq!(info_vlen, 0);

                Ok(BtfType::Const {
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                })
            }
            BTF_KIND_RESTRICT => {
                assert_eq!(name_offset, 0);
                assert!(!info_kind_flag);
                assert_eq!(info_vlen, 0);

                Ok(BtfType::Const {
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                })
            }
            BTF_KIND_FUNC => {
                assert!(!info_kind_flag);
                assert_eq!(info_vlen, 0);

                Ok(BtfType::Func {
                    name: strings.name(name_offset),
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                })
            }
            BTF_KIND_FUNC_PROTO => {
                assert_eq!(name_offset, 0);
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
            BTF_KIND_VAR => {
                assert!(!info_kind_flag);
                assert_eq!(info_vlen, 0);
                let var: btf_var = read(data).unwrap();

                Ok(BtfType::Var {
                    name: strings.name(name_offset),
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                    linkage: var.linkage,
                })
            }
            BTF_KIND_DATASEC => {
                assert!(!info_kind_flag);
                let info = (0..info_vlen)
                    .map(|_| {
                        let secinfo: btf_var_secinfo = read(data).unwrap();

                        SecInfo {
                            ty: secinfo.type_,
                            offset: secinfo.offset,
                            size: secinfo.size,
                        }
                    })
                    .collect();

                Ok(BtfType::DataSec {
                    name: strings.name(name_offset),
                    size: unsafe { ty.__bindgen_anon_1.size },
                    info,
                })
            }
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
            BTF_KIND_DECL_TAG => {
                assert!(!info_kind_flag);
                assert_eq!(info_vlen, 0);
                let decl_tag: btf_decl_tag = read(data).unwrap();
                // TODO: should we just check for -1?
                let component_idx = if decl_tag.component_idx < 0 {
                    None
                } else {
                    Some(decl_tag.component_idx as u32)
                };

                Ok(BtfType::DeclTag {
                    name: strings.name(name_offset),
                    ty: unsafe { ty.__bindgen_anon_1.type_ },
                    component_idx,
                })
            }
            // BTF_KIND_TYPE_TAG => {}
            k => panic!("unhandled kind: {k}"),
        }
    }
}

#[derive(Debug)]
pub enum IntEncoding {
    None,
    Signed,
    Char,
    Bool,
}

#[derive(Debug)]
pub struct Member {
    // per the docs this should be a valid identifier, however in
    // practice some struct/union members can be anonymous in that
    // they do not contain a name so we are making it optional to
    // account for that
    pub name: Option<String>,
    pub ty: u32,
    pub offset: u32,
    pub bitfield_size: Option<u8>,
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
pub struct EnumVariant {
    pub name: String,
    pub val: i32,
}

#[derive(Debug)]
pub struct SecInfo {
    pub ty: u32,
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug)]
pub struct FuncProtoParam {
    pub name: Option<String>,
    pub ty: u32,
}

#[derive(Debug)]
pub enum FwdKind {
    Struct,
    Union,
}

fn read<T: Copy>(data: &mut &[u8]) -> Result<T, ()> {
    if data.len() < std::mem::size_of::<T>() {
        return Err(());
    }

    let value = unsafe { std::ptr::read((*data).as_ptr() as *const T) };
    *data = &data[std::mem::size_of::<T>()..];

    Ok(value)
}

fn info_kind(ty: &btf_type) -> u32 {
    (ty.info >> 24) & 0x1f
}

fn info_vlen(ty: &btf_type) -> u16 {
    (ty.info & 0xFFFF) as u16
}

fn info_kind_flag(ty: &btf_type) -> bool {
    ty.info >> 31 == 1
}
