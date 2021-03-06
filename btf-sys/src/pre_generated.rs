/* automatically generated by rust-bindgen 0.59.2 */

pub const __BITS_PER_LONG: u32 = 64;
pub const __FD_SETSIZE: u32 = 1024;
pub const BTF_MAGIC: u32 = 60319;
pub const BTF_VERSION: u32 = 1;
pub const BTF_MAX_TYPE: u32 = 1048575;
pub const BTF_MAX_NAME_OFFSET: u32 = 16777215;
pub const BTF_MAX_VLEN: u32 = 65535;
pub const BTF_INT_SIGNED: u32 = 1;
pub const BTF_INT_CHAR: u32 = 2;
pub const BTF_INT_BOOL: u32 = 4;
pub type __s8 = ::std::os::raw::c_schar;
pub type __u8 = ::std::os::raw::c_uchar;
pub type __s16 = ::std::os::raw::c_short;
pub type __u16 = ::std::os::raw::c_ushort;
pub type __s32 = ::std::os::raw::c_int;
pub type __u32 = ::std::os::raw::c_uint;
pub type __s64 = ::std::os::raw::c_longlong;
pub type __u64 = ::std::os::raw::c_ulonglong;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __kernel_fd_set {
    pub fds_bits: [::std::os::raw::c_ulong; 16usize],
}
#[test]
fn bindgen_test_layout___kernel_fd_set() {
    assert_eq!(
        ::std::mem::size_of::<__kernel_fd_set>(),
        128usize,
        concat!("Size of: ", stringify!(__kernel_fd_set))
    );
    assert_eq!(
        ::std::mem::align_of::<__kernel_fd_set>(),
        8usize,
        concat!("Alignment of ", stringify!(__kernel_fd_set))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<__kernel_fd_set>())).fds_bits as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(__kernel_fd_set),
            "::",
            stringify!(fds_bits)
        )
    );
}
pub type __kernel_sighandler_t =
    ::std::option::Option<unsafe extern "C" fn(arg1: ::std::os::raw::c_int)>;
pub type __kernel_key_t = ::std::os::raw::c_int;
pub type __kernel_mqd_t = ::std::os::raw::c_int;
pub type __kernel_old_uid_t = ::std::os::raw::c_ushort;
pub type __kernel_old_gid_t = ::std::os::raw::c_ushort;
pub type __kernel_old_dev_t = ::std::os::raw::c_ulong;
pub type __kernel_long_t = ::std::os::raw::c_long;
pub type __kernel_ulong_t = ::std::os::raw::c_ulong;
pub type __kernel_ino_t = __kernel_ulong_t;
pub type __kernel_mode_t = ::std::os::raw::c_uint;
pub type __kernel_pid_t = ::std::os::raw::c_int;
pub type __kernel_ipc_pid_t = ::std::os::raw::c_int;
pub type __kernel_uid_t = ::std::os::raw::c_uint;
pub type __kernel_gid_t = ::std::os::raw::c_uint;
pub type __kernel_suseconds_t = __kernel_long_t;
pub type __kernel_daddr_t = ::std::os::raw::c_int;
pub type __kernel_uid32_t = ::std::os::raw::c_uint;
pub type __kernel_gid32_t = ::std::os::raw::c_uint;
pub type __kernel_size_t = __kernel_ulong_t;
pub type __kernel_ssize_t = __kernel_long_t;
pub type __kernel_ptrdiff_t = __kernel_long_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __kernel_fsid_t {
    pub val: [::std::os::raw::c_int; 2usize],
}
#[test]
fn bindgen_test_layout___kernel_fsid_t() {
    assert_eq!(
        ::std::mem::size_of::<__kernel_fsid_t>(),
        8usize,
        concat!("Size of: ", stringify!(__kernel_fsid_t))
    );
    assert_eq!(
        ::std::mem::align_of::<__kernel_fsid_t>(),
        4usize,
        concat!("Alignment of ", stringify!(__kernel_fsid_t))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<__kernel_fsid_t>())).val as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(__kernel_fsid_t),
            "::",
            stringify!(val)
        )
    );
}
pub type __kernel_off_t = __kernel_long_t;
pub type __kernel_loff_t = ::std::os::raw::c_longlong;
pub type __kernel_old_time_t = __kernel_long_t;
pub type __kernel_time_t = __kernel_long_t;
pub type __kernel_time64_t = ::std::os::raw::c_longlong;
pub type __kernel_clock_t = __kernel_long_t;
pub type __kernel_timer_t = ::std::os::raw::c_int;
pub type __kernel_clockid_t = ::std::os::raw::c_int;
pub type __kernel_caddr_t = *mut ::std::os::raw::c_char;
pub type __kernel_uid16_t = ::std::os::raw::c_ushort;
pub type __kernel_gid16_t = ::std::os::raw::c_ushort;
pub type __le16 = __u16;
pub type __be16 = __u16;
pub type __le32 = __u32;
pub type __be32 = __u32;
pub type __le64 = __u64;
pub type __be64 = __u64;
pub type __sum16 = __u16;
pub type __wsum = __u32;
pub type __poll_t = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct btf_header {
    pub magic: __u16,
    pub version: __u8,
    pub flags: __u8,
    pub hdr_len: __u32,
    pub type_off: __u32,
    pub type_len: __u32,
    pub str_off: __u32,
    pub str_len: __u32,
}
#[test]
fn bindgen_test_layout_btf_header() {
    assert_eq!(
        ::std::mem::size_of::<btf_header>(),
        24usize,
        concat!("Size of: ", stringify!(btf_header))
    );
    assert_eq!(
        ::std::mem::align_of::<btf_header>(),
        4usize,
        concat!("Alignment of ", stringify!(btf_header))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_header>())).magic as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_header),
            "::",
            stringify!(magic)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_header>())).version as *const _ as usize },
        2usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_header),
            "::",
            stringify!(version)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_header>())).flags as *const _ as usize },
        3usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_header),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_header>())).hdr_len as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_header),
            "::",
            stringify!(hdr_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_header>())).type_off as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_header),
            "::",
            stringify!(type_off)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_header>())).type_len as *const _ as usize },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_header),
            "::",
            stringify!(type_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_header>())).str_off as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_header),
            "::",
            stringify!(str_off)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_header>())).str_len as *const _ as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_header),
            "::",
            stringify!(str_len)
        )
    );
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct btf_type {
    pub name_off: __u32,
    pub info: __u32,
    pub __bindgen_anon_1: btf_type__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union btf_type__bindgen_ty_1 {
    pub size: __u32,
    pub type_: __u32,
}
#[test]
fn bindgen_test_layout_btf_type__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<btf_type__bindgen_ty_1>(),
        4usize,
        concat!("Size of: ", stringify!(btf_type__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<btf_type__bindgen_ty_1>(),
        4usize,
        concat!("Alignment of ", stringify!(btf_type__bindgen_ty_1))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_type__bindgen_ty_1>())).size as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_type__bindgen_ty_1),
            "::",
            stringify!(size)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_type__bindgen_ty_1>())).type_ as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_type__bindgen_ty_1),
            "::",
            stringify!(type_)
        )
    );
}
#[test]
fn bindgen_test_layout_btf_type() {
    assert_eq!(
        ::std::mem::size_of::<btf_type>(),
        12usize,
        concat!("Size of: ", stringify!(btf_type))
    );
    assert_eq!(
        ::std::mem::align_of::<btf_type>(),
        4usize,
        concat!("Alignment of ", stringify!(btf_type))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_type>())).name_off as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_type),
            "::",
            stringify!(name_off)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_type>())).info as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_type),
            "::",
            stringify!(info)
        )
    );
}
pub const BTF_KIND_UNKN: ::std::os::raw::c_uint = 0;
pub const BTF_KIND_INT: ::std::os::raw::c_uint = 1;
pub const BTF_KIND_PTR: ::std::os::raw::c_uint = 2;
pub const BTF_KIND_ARRAY: ::std::os::raw::c_uint = 3;
pub const BTF_KIND_STRUCT: ::std::os::raw::c_uint = 4;
pub const BTF_KIND_UNION: ::std::os::raw::c_uint = 5;
pub const BTF_KIND_ENUM: ::std::os::raw::c_uint = 6;
pub const BTF_KIND_FWD: ::std::os::raw::c_uint = 7;
pub const BTF_KIND_TYPEDEF: ::std::os::raw::c_uint = 8;
pub const BTF_KIND_VOLATILE: ::std::os::raw::c_uint = 9;
pub const BTF_KIND_CONST: ::std::os::raw::c_uint = 10;
pub const BTF_KIND_RESTRICT: ::std::os::raw::c_uint = 11;
pub const BTF_KIND_FUNC: ::std::os::raw::c_uint = 12;
pub const BTF_KIND_FUNC_PROTO: ::std::os::raw::c_uint = 13;
pub const BTF_KIND_VAR: ::std::os::raw::c_uint = 14;
pub const BTF_KIND_DATASEC: ::std::os::raw::c_uint = 15;
pub const BTF_KIND_FLOAT: ::std::os::raw::c_uint = 16;
pub const BTF_KIND_DECL_TAG: ::std::os::raw::c_uint = 17;
pub const NR_BTF_KINDS: ::std::os::raw::c_uint = 18;
pub const BTF_KIND_MAX: ::std::os::raw::c_uint = 17;
pub type _bindgen_ty_1 = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct btf_enum {
    pub name_off: __u32,
    pub val: __s32,
}
#[test]
fn bindgen_test_layout_btf_enum() {
    assert_eq!(
        ::std::mem::size_of::<btf_enum>(),
        8usize,
        concat!("Size of: ", stringify!(btf_enum))
    );
    assert_eq!(
        ::std::mem::align_of::<btf_enum>(),
        4usize,
        concat!("Alignment of ", stringify!(btf_enum))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_enum>())).name_off as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_enum),
            "::",
            stringify!(name_off)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_enum>())).val as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_enum),
            "::",
            stringify!(val)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct btf_array {
    pub type_: __u32,
    pub index_type: __u32,
    pub nelems: __u32,
}
#[test]
fn bindgen_test_layout_btf_array() {
    assert_eq!(
        ::std::mem::size_of::<btf_array>(),
        12usize,
        concat!("Size of: ", stringify!(btf_array))
    );
    assert_eq!(
        ::std::mem::align_of::<btf_array>(),
        4usize,
        concat!("Alignment of ", stringify!(btf_array))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_array>())).type_ as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_array),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_array>())).index_type as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_array),
            "::",
            stringify!(index_type)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_array>())).nelems as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_array),
            "::",
            stringify!(nelems)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct btf_member {
    pub name_off: __u32,
    pub type_: __u32,
    pub offset: __u32,
}
#[test]
fn bindgen_test_layout_btf_member() {
    assert_eq!(
        ::std::mem::size_of::<btf_member>(),
        12usize,
        concat!("Size of: ", stringify!(btf_member))
    );
    assert_eq!(
        ::std::mem::align_of::<btf_member>(),
        4usize,
        concat!("Alignment of ", stringify!(btf_member))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_member>())).name_off as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_member),
            "::",
            stringify!(name_off)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_member>())).type_ as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_member),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_member>())).offset as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_member),
            "::",
            stringify!(offset)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct btf_param {
    pub name_off: __u32,
    pub type_: __u32,
}
#[test]
fn bindgen_test_layout_btf_param() {
    assert_eq!(
        ::std::mem::size_of::<btf_param>(),
        8usize,
        concat!("Size of: ", stringify!(btf_param))
    );
    assert_eq!(
        ::std::mem::align_of::<btf_param>(),
        4usize,
        concat!("Alignment of ", stringify!(btf_param))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_param>())).name_off as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_param),
            "::",
            stringify!(name_off)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_param>())).type_ as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_param),
            "::",
            stringify!(type_)
        )
    );
}
pub const BTF_VAR_STATIC: ::std::os::raw::c_uint = 0;
pub const BTF_VAR_GLOBAL_ALLOCATED: ::std::os::raw::c_uint = 1;
pub const BTF_VAR_GLOBAL_EXTERN: ::std::os::raw::c_uint = 2;
pub type _bindgen_ty_2 = ::std::os::raw::c_uint;
pub const btf_func_linkage_BTF_FUNC_STATIC: btf_func_linkage = 0;
pub const btf_func_linkage_BTF_FUNC_GLOBAL: btf_func_linkage = 1;
pub const btf_func_linkage_BTF_FUNC_EXTERN: btf_func_linkage = 2;
pub type btf_func_linkage = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct btf_var {
    pub linkage: __u32,
}
#[test]
fn bindgen_test_layout_btf_var() {
    assert_eq!(
        ::std::mem::size_of::<btf_var>(),
        4usize,
        concat!("Size of: ", stringify!(btf_var))
    );
    assert_eq!(
        ::std::mem::align_of::<btf_var>(),
        4usize,
        concat!("Alignment of ", stringify!(btf_var))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_var>())).linkage as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_var),
            "::",
            stringify!(linkage)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct btf_var_secinfo {
    pub type_: __u32,
    pub offset: __u32,
    pub size: __u32,
}
#[test]
fn bindgen_test_layout_btf_var_secinfo() {
    assert_eq!(
        ::std::mem::size_of::<btf_var_secinfo>(),
        12usize,
        concat!("Size of: ", stringify!(btf_var_secinfo))
    );
    assert_eq!(
        ::std::mem::align_of::<btf_var_secinfo>(),
        4usize,
        concat!("Alignment of ", stringify!(btf_var_secinfo))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_var_secinfo>())).type_ as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_var_secinfo),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_var_secinfo>())).offset as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_var_secinfo),
            "::",
            stringify!(offset)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_var_secinfo>())).size as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_var_secinfo),
            "::",
            stringify!(size)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct btf_decl_tag {
    pub component_idx: __s32,
}
#[test]
fn bindgen_test_layout_btf_decl_tag() {
    assert_eq!(
        ::std::mem::size_of::<btf_decl_tag>(),
        4usize,
        concat!("Size of: ", stringify!(btf_decl_tag))
    );
    assert_eq!(
        ::std::mem::align_of::<btf_decl_tag>(),
        4usize,
        concat!("Alignment of ", stringify!(btf_decl_tag))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<btf_decl_tag>())).component_idx as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(btf_decl_tag),
            "::",
            stringify!(component_idx)
        )
    );
}
