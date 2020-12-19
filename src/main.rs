use std::fmt;

use redbpf::load::{Loader, LoaderError};

#[derive(Debug)]
enum MainError {
    Loader(LoaderError),
}

impl fmt::Display for MainError {
    fn fmt(self: &Self, f: &mut fmt::Formatter) -> fmt::Result {
        use MainError::*;
        write!(
            f,
            "{}",
            match self {
                Loader(e) => format!("loader {:?}", e),
            }
        )
    }
}

fn main() -> Result<(), MainError> {
    let sockmap_parser_elf =
        include_bytes!("../target/bpf/programs/sockmap_parser/sockmap_parser.elf");
    println!("elf is {} bytes", sockmap_parser_elf.len());

    let mut loader = Loader::load(sockmap_parser_elf).map_err(MainError::Loader)?;
    for socket_filter in loader.socket_filters_mut() {
        println!("found socket_filter");
    }

    Ok(())
}
