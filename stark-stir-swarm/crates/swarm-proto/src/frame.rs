//! Length-prefixed CBOR framing over an async byte stream.
//!
//! Each frame is `u32-be-length ‖ cbor-payload`. The length field excludes
//! itself and is capped at `MAX_FRAME_BYTES` to bound peer-controlled
//! allocation.

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum encoded frame size (16 MiB). Comfortably above any wire message
/// we plan to send — register/heartbeat are <1 KiB; future shard assignment
/// payloads serialise the records list, which fits well under the cap.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame too large: {0} bytes (max {MAX_FRAME_BYTES})")]
    TooLarge(usize),
    #[error("cbor encode: {0}")]
    Encode(String),
    #[error("cbor decode: {0}")]
    Decode(String),
}

/// Encode `msg` as CBOR and write a length-prefixed frame.
pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut buf = Vec::with_capacity(256);
    ciborium::ser::into_writer(msg, &mut buf).map_err(|e| FrameError::Encode(e.to_string()))?;
    if buf.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(buf.len()));
    }
    let len = (buf.len() as u32).to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Read a length-prefixed CBOR frame and decode it.
pub async fn read_frame<R, T>(r: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    let msg = ciborium::de::from_reader(payload.as_slice())
        .map_err(|e| FrameError::Decode(e.to_string()))?;
    Ok(msg)
}
