//! Collecteurs Linux (§7.3). Les extracteurs sont purs (texte → faits) ;
//! seule la lecture des fichiers systèmes est derrière `#[cfg(unix)]`.

pub mod accounts;
pub mod sshd;
pub mod sudoers;
