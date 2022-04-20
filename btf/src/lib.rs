mod strings;
mod types;

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
};

use btf_sys::btf_header;
pub use strings::StringsTable;
pub use types::{BtfType, Member};

pub struct Btf {
    types: Vec<u8>,
    strings: StringsTable,
}

impl Btf {
    pub fn read(mut file: File) -> Result<Self, io::Error> {
        let header = read_header(&mut file)?;

        let mut types: Vec<u8> = vec![0; header.type_len as usize];
        let mut strings: Vec<u8> = vec![0; header.str_len as usize];

        if header.type_off < header.str_off {
            file.seek(SeekFrom::Current(header.type_off as i64))?;
            file.read_exact(&mut types)?;

            file.seek(SeekFrom::Current((header.str_off - header.type_len) as i64))?;
            file.read_exact(&mut strings)?;
        } else {
            file.seek(SeekFrom::Current(header.str_off as i64))?;
            file.read_exact(&mut strings)?;

            file.seek(SeekFrom::Current((header.type_off - header.str_len) as i64))?;
            file.read_exact(&mut types)?;
        };

        Ok(Btf {
            types,
            strings: StringsTable(strings),
        })
    }

    pub fn types(&self) -> impl Iterator<Item = BtfType> + '_ {
        TypeIterator {
            types: &self.types,
            strings: &self.strings,
        }
    }
}

struct TypeIterator<'b> {
    types: &'b [u8],
    strings: &'b StringsTable,
}

impl<'b> Iterator for TypeIterator<'b> {
    type Item = BtfType;

    fn next(&mut self) -> Option<Self::Item> {
        BtfType::read_from(&mut self.types, self.strings).ok()
    }
}

fn read_header(mut buffer: impl Read + Seek) -> Result<btf_header, io::Error> {
    let header: btf_header = unsafe {
        let mut header = [0_u8; std::mem::size_of::<btf_header>()];
        buffer.read_exact(&mut header)?;
        std::mem::transmute(header)
    };

    if header.magic != MAGIC {
        panic!("the parsed vmlinux does not match machine's endian-ness");
    }

    let offset: i64 = header.hdr_len as i64 - std::mem::size_of::<btf_header>() as i64;

    // skip the header fields we do not know about
    buffer.seek(SeekFrom::Current(offset))?;

    Ok(header)
}

const MAGIC: u16 = 0xEB9F;
