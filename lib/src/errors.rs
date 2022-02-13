use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Not implemented yet")]
    TBD,

    #[error(transparent)]
    Io(#[from] io::Error),
}
