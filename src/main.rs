use std::fs::File;

use btf::{Btf, BtfType};

fn main() {
    let file = File::open("/sys/kernel/btf/vmlinux").unwrap();
    let btf = Btf::read(file).unwrap();

    for ty in btf.types() {
        if let BtfType::Struct {
            name,
            size,
            members,
        } = ty
        {
            println!("struct {:?}, size: {}, members: {:#?}", name, size, members);
        }
    }
}
