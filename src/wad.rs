use getset::{CopyGetters, Getters};
use num_enum::TryFromPrimitive;
use std::{
    collections::{hash_map, HashMap},
    convert::TryFrom,
    io::{self, Read, Seek},
    path::Path,
};
use thiserror::Error;

use crate::streaming::binary_reader::BinaryReader;

#[derive(Error, Debug)]
pub enum WadError {
    #[error("{0}")]
    IoError(io::Error),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Unsupported version: {0}.{1}")]
    UnsupportedVersion(u8, u8),
    #[error("An entry with the same path hash already exists: {0}")]
    DuplicateEntry(u64),
    #[error("Unknown entry data format: {0}")]
    UnknownEntryDataFormat(u8),
}

impl From<io::Error> for WadError {
    fn from(error: io::Error) -> Self {
        WadError::IoError(error)
    }
}

pub struct Wad {
    signature: Vec<u8>,

    entries: HashMap<u64, Entry>,
}

#[derive(Getters, CopyGetters)]
pub struct Entry {
    #[getset(get_copy = "pub")]
    xxhash: u64,

    #[getset(get_copy = "pub")]
    compressed_size: i32,
    #[getset(get_copy = "pub")]
    uncompressed_size: i32,

    #[getset(get_copy = "pub")]
    data_format: EntryDataFormat,
    #[getset(get = "pub")]
    data_checksum: EntryDataChecksum,
    #[getset(get_copy = "pub(crate)")]
    data_offset: u32,
    #[getset(get_copy = "pub(crate)")]
    is_duplicated: bool,
}

#[derive(Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum EntryDataFormat {
    Raw,
    GZip,
    FileRedirection,
    Zstd,
    Unknown,
}

pub enum EntryDataChecksum {
    Sha256(Vec<u8>),
    XxHash3(Vec<u8>),
    None,
}

impl Wad {
    pub fn mount_from_path(path: &Path) -> Result<Self, WadError> {
        let mut br = BinaryReader::from_location(path);

        Self::read(&mut br)
    }

    fn read<R: Read + Seek>(br: &mut BinaryReader<R>) -> Result<Self, WadError> {
        let magic = br.read_string(2)?;
        if magic != "RW" {
            return Err(WadError::InvalidSignature(magic));
        }

        let major = br.read_u8()?;
        let minor = br.read_u8()?;
        if major > 3 {
            return Err(WadError::UnsupportedVersion(major, minor));
        }

        let signature = match major {
            2 => {
                let length = br.read_u8()? as usize;
                br.read_bytes(83 - length)?
            }
            3 => br.read_bytes(256)?,
            _ => Vec::new(),
        };

        let mut _unknown1 = br.read_u64()?;

        if major == 1 || major == 2 {
            let _toc_start_offset = br.read_u16()?;
            let _toc_file_entry_size = br.read_u16()?;
        }

        let entry_count = br.read_u32()?;
        let mut entries = HashMap::<u64, Entry>::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            let entry = Entry::read(br, major, minor)?;

            match entries.entry(entry.xxhash()) {
                hash_map::Entry::Occupied(_) => Err(WadError::DuplicateEntry(entry.xxhash())),
                hash_map::Entry::Vacant(hashmap_entry) => Ok(hashmap_entry.insert(entry)),
            }?;
        }

        Ok(Wad { signature, entries })
    }
}

impl Entry {
    pub(crate) fn read<R: Read + Seek>(
        br: &mut BinaryReader<R>,
        major: u8,
        minor: u8,
    ) -> Result<Self, WadError> {
        let xxhash = br.read_u64()?;
        let data_offset = br.read_u32()?;
        let compressed_size = br.read_i32()?;
        let uncompressed_size = br.read_i32()?;
        let data_format = match EntryDataFormat::try_from(br.read_u8()?) {
            Ok(value) => Ok(value),
            Err(error) => Err(WadError::UnknownEntryDataFormat(error.number)),
        }?;
        let is_duplicated = br.read_u8()? == 1;

        br.read_u16()?;

        let data_checksum = if major >= 2 {
            if major == 3 && minor == 1 {
                EntryDataChecksum::XxHash3(br.read_bytes(8)?)
            } else {
                EntryDataChecksum::Sha256(br.read_bytes(8)?)
            }
        } else {
            EntryDataChecksum::None
        };

        Ok(Entry {
            xxhash,
            data_offset,
            compressed_size,
            uncompressed_size,
            data_format,
            is_duplicated,
            data_checksum,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::wad::Wad;

    #[test]
    fn test_read() {
        let wad = Wad::mount_from_path(Path::new(
            "C:/Riot Games/League of Legends/Game/DATA/FINAL/Champions/Aatrox.wad.client",
        ));

        assert!(wad.is_ok())
    }
}
