//! Collecteurs Linux (§7.3). Les extracteurs sont purs (texte → faits) ;
//! seule la lecture des fichiers systèmes est derrière `#[cfg(unix)]`.

pub mod accounts;
pub mod kernel_params;
pub mod packages;
pub mod ports;
pub mod sshd;
pub mod sudoers;
pub mod systemd;
