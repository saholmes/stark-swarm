//! Wire protocol + post-quantum TLS layer for the STIR DNS swarm.
//!
//! Transport stack (option A — standards-track hybrid TLS 1.3):
//!
//! ```text
//!     ┌────────────── application messages ──────────────┐
//!     │  CBOR-encoded `ClientMsg` / `ServerMsg`           │
//!     ├────────────── length-prefixed framing ────────────┤
//!     │  u32 length (BE) ‖ payload                        │
//!     ├────────────── tokio-rustls TLS 1.3 ───────────────┤
//!     │  X25519+ML-KEM-768 hybrid KEX                     │
//!     │  classical Ed25519/ECDSA cert chain (self-signed) │
//!     │  AEAD: AES-128-GCM or ChaCha20-Poly1305           │
//!     ├────────────── tokio TCP socket ───────────────────┤
//!     │  v4 / v6                                          │
//!     └───────────────────────────────────────────────────┘
//! ```

pub mod cert;
pub mod frame;
pub mod messages;
pub mod tls;

pub use messages::{Capabilities, ClientMsg, ServerMsg, WorkerId};
