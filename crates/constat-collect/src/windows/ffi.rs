//! FFI Win32 — **tout le code `unsafe` du crate est confiné ici**, en LECTURE
//! SEULE stricte : `NetUserEnum`, `NetLocalGroupEnum`, `NetLocalGroupGetMembers`,
//! `NetUserModalsGet`, `NetGroupEnum`, `NetGroupGetUsers`, `DsGetDcName`,
//! `LookupAccountName` et la lecture du registre (`KEY_READ`). Aucune de ces
//! API n'écrit quoi que ce soit ; aucune commande n'est exécutée (§7.1).
//!
//! Chaque fonction publique produit la **capture texte normalisée** attendue
//! par l'extracteur pur du collecteur correspondant : la sémantique reste
//! entièrement testable hors Windows, ce module ne fait que de la plomberie.
//!
//! Les tampons rendus par `netapi32` sont libérés par un garde RAII
//! ([`NetBuffer`]) ; les clefs de registre par [`RegKey`]. Jamais de panique :
//! toute erreur d'API remonte en `Err(String)` avec le code Win32.

// Le workspace interdit `unsafe_code` (« forbid ») ; ce crate l'abaisse à
// « deny » dans son Cargo.toml, et ce seul module l'autorise : la FFI Win32
// est intrinsèquement `unsafe`, et chaque bloc est justifié par un SAFETY.
#![allow(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS,
    FILETIME,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetGroupEnum, NetGroupGetUsers, NetLocalGroupEnum, NetLocalGroupGetMembers,
    NetUserEnum, NetUserModalsGet, FILTER_NORMAL_ACCOUNT, GROUP_INFO_0, GROUP_USERS_INFO_0,
    LOCALGROUP_INFO_0, LOCALGROUP_MEMBERS_INFO_1, MAX_PREFERRED_LENGTH, UF_ACCOUNTDISABLE,
    UF_DONT_EXPIRE_PASSWD, USER_INFO_3, USER_MODALS_INFO_0, USER_MODALS_INFO_3,
};
use windows_sys::Win32::Networking::ActiveDirectory::DsGetDcNameW;
use windows_sys::Win32::Security::{LookupAccountNameW, PSID, SID_NAME_USE};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_READ, REG_VALUE_TYPE,
};

use crate::windows::format_sid_bytes;

// ---------------------------------------------------------------------------
// Aides communes
// ---------------------------------------------------------------------------

/// Chaîne UTF-16 terminée par NUL, pour les paramètres `PCWSTR`.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Lit une chaîne UTF-16 terminée par NUL (pointeur d'API Win32).
///
/// SAFETY (appelant) : `p` est nul ou pointe une chaîne NUL-terminée valide,
/// telle que rendue par l'API système.
unsafe fn pwstr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY : contrat de l'appelant — la chaîne est NUL-terminée.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY : `len` unités valides viennent d'être comptées.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

/// Neutralise les caractères de contrôle d'une valeur avant insertion dans la
/// capture INI (une valeur hostile ne doit pas pouvoir injecter une ligne).
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Garde RAII : libère un tampon `netapi32` (`NetApiBufferFree`).
struct NetBuffer(*mut u8);

impl Drop for NetBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY : le pointeur vient d'une API NetXxx et n'est libéré qu'ici.
            unsafe { NetApiBufferFree(self.0 as *const core::ffi::c_void) };
        }
    }
}

/// Formate un `PSID` d'API en SID textuel via le formateur pur
/// ([`format_sid_bytes`]).
///
/// SAFETY (appelant) : `psid` est nul ou pointe un SID valide rendu par l'API.
unsafe fn psid_to_string(psid: PSID) -> Option<String> {
    if psid.is_null() {
        return None;
    }
    // SAFETY : un SID valide fait au moins 8 octets (révision, compte,
    // autorité) ; l'octet 1 donne le nombre de sous-autorités.
    let head = unsafe { std::slice::from_raw_parts(psid as *const u8, 8) };
    let len = 8 + head[1] as usize * 4;
    // SAFETY : par contrat de l'API, le SID occupe bien `len` octets.
    let all = unsafe { std::slice::from_raw_parts(psid as *const u8, len) };
    format_sid_bytes(all)
}

/// Résout le SID d'un compte (`LookupAccountName`, deux passes). `system` :
/// `None` pour la machine locale, `Some(serveur)` pour un contrôleur de
/// domaine. `None` si le compte est introuvable — jamais de panique.
fn lookup_account_sid(system: Option<&str>, account: &str) -> Option<String> {
    let system_w = system.map(to_wide);
    let system_ptr = system_w.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());
    let account_w = to_wide(account);
    let mut cb_sid: u32 = 0;
    let mut cch_domain: u32 = 0;
    let mut sid_use: SID_NAME_USE = 0;
    // SAFETY : première passe avec tampons nuls, uniquement pour les tailles.
    let ok = unsafe {
        LookupAccountNameW(
            system_ptr,
            account_w.as_ptr(),
            std::ptr::null_mut(),
            &mut cb_sid,
            std::ptr::null_mut(),
            &mut cch_domain,
            &mut sid_use,
        )
    };
    // SAFETY : GetLastError est toujours appelable.
    if ok == 0 && unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }
    if cb_sid == 0 {
        return None;
    }
    let mut sid = vec![0u8; cb_sid as usize];
    let mut domain = vec![0u16; cch_domain.max(1) as usize];
    // SAFETY : les tampons ont exactement les tailles annoncées par l'API.
    let ok = unsafe {
        LookupAccountNameW(
            system_ptr,
            account_w.as_ptr(),
            sid.as_mut_ptr() as PSID,
            &mut cb_sid,
            domain.as_mut_ptr(),
            &mut cch_domain,
            &mut sid_use,
        )
    };
    if ok == 0 {
        return None;
    }
    format_sid_bytes(&sid)
}

// ---------------------------------------------------------------------------
// windows.accounts
// ---------------------------------------------------------------------------

struct UserRow {
    name: String,
    flags: u32,
    /// Secondes UTC depuis l'époque Unix (0 = jamais connecté).
    last_logon: u32,
}

/// Énumère les comptes locaux (`NetUserEnum` niveau 3, comptes normaux).
fn enum_users() -> Result<Vec<UserRow>, String> {
    let mut rows: Vec<UserRow> = Vec::new();
    let mut resume: u32 = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read: u32 = 0;
        let mut total: u32 = 0;
        // SAFETY : appel documenté ; le tampon rendu est libéré par NetBuffer.
        let status = unsafe {
            NetUserEnum(
                std::ptr::null(),
                3,
                FILTER_NORMAL_ACCOUNT,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        let _guard = NetBuffer(buf);
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(format!("NetUserEnum : code {status}"));
        }
        if !buf.is_null() && read > 0 {
            // SAFETY : l'API garantit `read` entrées USER_INFO_3 dans le tampon.
            let entries =
                unsafe { std::slice::from_raw_parts(buf as *const USER_INFO_3, read as usize) };
            for e in entries {
                // SAFETY : usri3_name est une chaîne NUL-terminée de l'API.
                let name = unsafe { pwstr_to_string(e.usri3_name) };
                if name.is_empty() {
                    continue;
                }
                rows.push(UserRow {
                    name,
                    flags: e.usri3_flags,
                    last_logon: e.usri3_last_logon,
                });
            }
        }
        if status != ERROR_MORE_DATA {
            return Ok(rows);
        }
    }
}

/// Énumère les groupes locaux (`NetLocalGroupEnum` niveau 0) — noms seulement.
fn enum_local_groups() -> Result<Vec<String>, String> {
    let mut names: Vec<String> = Vec::new();
    let mut resume: usize = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read: u32 = 0;
        let mut total: u32 = 0;
        // SAFETY : appel documenté ; tampon libéré par NetBuffer.
        let status = unsafe {
            NetLocalGroupEnum(
                std::ptr::null(),
                0,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        let _guard = NetBuffer(buf);
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(format!("NetLocalGroupEnum : code {status}"));
        }
        if !buf.is_null() && read > 0 {
            // SAFETY : `read` entrées LOCALGROUP_INFO_0 garanties par l'API.
            let entries = unsafe {
                std::slice::from_raw_parts(buf as *const LOCALGROUP_INFO_0, read as usize)
            };
            for e in entries {
                // SAFETY : chaîne NUL-terminée de l'API.
                let name = unsafe { pwstr_to_string(e.lgrpi0_name) };
                if !name.is_empty() {
                    names.push(name);
                }
            }
        }
        if status != ERROR_MORE_DATA {
            return Ok(names);
        }
    }
}

/// SID des membres d'un groupe local (`NetLocalGroupGetMembers` niveau 1).
/// Un groupe illisible (accès refusé, supprimé entre-temps) rend une liste
/// vide : la collecte des autres groupes continue.
fn local_group_member_sids(group: &str) -> BTreeSet<String> {
    let group_w = to_wide(group);
    let mut sids: BTreeSet<String> = BTreeSet::new();
    let mut resume: usize = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read: u32 = 0;
        let mut total: u32 = 0;
        // SAFETY : appel documenté ; tampon libéré par NetBuffer.
        let status = unsafe {
            NetLocalGroupGetMembers(
                std::ptr::null(),
                group_w.as_ptr(),
                1,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        let _guard = NetBuffer(buf);
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return sids;
        }
        if !buf.is_null() && read > 0 {
            // SAFETY : `read` entrées LOCALGROUP_MEMBERS_INFO_1 garanties.
            let entries = unsafe {
                std::slice::from_raw_parts(buf as *const LOCALGROUP_MEMBERS_INFO_1, read as usize)
            };
            for e in entries {
                // SAFETY : lgrmi1_sid est un SID valide rendu par l'API.
                if let Some(sid) = unsafe { psid_to_string(e.lgrmi1_sid) } {
                    sids.insert(sid);
                }
            }
        }
        if status != ERROR_MORE_DATA {
            return sids;
        }
    }
}

/// Capture normalisée du collecteur `windows.accounts` (voir le format dans
/// [`crate::windows::accounts`]).
pub fn collect_accounts_capture() -> Result<String, String> {
    let users = enum_users()?;
    let groups = enum_local_groups()?;

    // SID de chaque groupe local, et SID → membres
    let mut group_sid_to_name: BTreeMap<String, String> = BTreeMap::new();
    let mut group_members: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for group in &groups {
        let Some(sid) = lookup_account_sid(None, group) else {
            continue; // groupe sans SID résoluble : ignoré, jamais de panique
        };
        group_members.insert(sid.clone(), local_group_member_sids(group));
        group_sid_to_name
            .entry(sid)
            .or_insert_with(|| group.clone());
    }

    // utilisateurs, triés par nom (BTreeMap : capture déterministe)
    let mut user_rows: BTreeMap<String, (String, u32, u32)> = BTreeMap::new();
    for row in users {
        let sid = lookup_account_sid(None, &row.name).unwrap_or_else(|| "inconnu".to_string());
        user_rows
            .entry(row.name.clone())
            .or_insert((sid, row.flags, row.last_logon));
    }

    let mut out = String::new();
    for (sid, name) in &group_sid_to_name {
        let _ = writeln!(out, "[localgroup {sid}]");
        let _ = writeln!(out, "name = {}", clean(name));
        out.push('\n');
    }
    for (name, (sid, flags, last_logon)) in &user_rows {
        let _ = writeln!(out, "[user {sid}]");
        let _ = writeln!(out, "name = {}", clean(name));
        let _ = writeln!(out, "enabled = {}", flags & UF_ACCOUNTDISABLE == 0);
        let _ = writeln!(
            out,
            "password_never_expires = {}",
            flags & UF_DONT_EXPIRE_PASSWD != 0
        );
        if *last_logon != 0 {
            // secondes → millisecondes UTC (précision du modèle, §15)
            let _ = writeln!(out, "last_logon = {}", i64::from(*last_logon) * 1000);
        }
        let member_of: Vec<&str> = group_members
            .iter()
            .filter(|(_, members)| members.contains(sid))
            .map(|(gsid, _)| gsid.as_str())
            .collect();
        let _ = writeln!(out, "groups = {}", member_of.join(","));
        out.push('\n');
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// windows.password_policy
// ---------------------------------------------------------------------------

/// Capture normalisée du collecteur `windows.password_policy`
/// (`NetUserModalsGet` niveaux 0 et 3, durées en secondes brutes).
pub fn collect_password_policy_capture() -> Result<String, String> {
    let mut buf0: *mut u8 = std::ptr::null_mut();
    // SAFETY : appel documenté ; tampon libéré par NetBuffer.
    let status = unsafe { NetUserModalsGet(std::ptr::null(), 0, &mut buf0) };
    let guard0 = NetBuffer(buf0);
    if status != ERROR_SUCCESS || buf0.is_null() {
        return Err(format!("NetUserModalsGet(0) : code {status}"));
    }
    // SAFETY : niveau 0 → le tampon contient un USER_MODALS_INFO_0.
    let m0 = unsafe { *(buf0 as *const USER_MODALS_INFO_0) };
    drop(guard0);

    let mut buf3: *mut u8 = std::ptr::null_mut();
    // SAFETY : appel documenté ; tampon libéré par NetBuffer.
    let status = unsafe { NetUserModalsGet(std::ptr::null(), 3, &mut buf3) };
    let guard3 = NetBuffer(buf3);
    if status != ERROR_SUCCESS || buf3.is_null() {
        return Err(format!("NetUserModalsGet(3) : code {status}"));
    }
    // SAFETY : niveau 3 → le tampon contient un USER_MODALS_INFO_3.
    let m3 = unsafe { *(buf3 as *const USER_MODALS_INFO_3) };
    drop(guard3);

    let mut out = String::from("[password_policy]\n");
    let _ = writeln!(out, "min_password_length = {}", m0.usrmod0_min_passwd_len);
    let _ = writeln!(
        out,
        "min_password_age_seconds = {}",
        m0.usrmod0_min_passwd_age
    );
    let _ = writeln!(
        out,
        "max_password_age_seconds = {}",
        m0.usrmod0_max_passwd_age
    );
    let _ = writeln!(
        out,
        "password_history_length = {}",
        m0.usrmod0_password_hist_len
    );
    let _ = writeln!(out, "lockout_threshold = {}", m3.usrmod3_lockout_threshold);
    let _ = writeln!(
        out,
        "lockout_duration_seconds = {}",
        m3.usrmod3_lockout_duration
    );
    let _ = writeln!(
        out,
        "lockout_observation_seconds = {}",
        m3.usrmod3_lockout_observation_window
    );
    Ok(out)
}

// ---------------------------------------------------------------------------
// windows.services — registre, KEY_READ uniquement
// ---------------------------------------------------------------------------

/// Garde RAII d'une clef de registre ouverte.
struct RegKey(HKEY);

impl Drop for RegKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY : la clef a été ouverte par RegOpenKeyExW dans ce module.
            unsafe { RegCloseKey(self.0) };
        }
    }
}

impl RegKey {
    /// Ouvre une sous-clef en lecture seule.
    fn open(parent: HKEY, path: &str) -> Option<RegKey> {
        let path_w = to_wide(path);
        let mut hkey: HKEY = std::ptr::null_mut();
        // SAFETY : appel documenté, accès KEY_READ strictement.
        let status = unsafe { RegOpenKeyExW(parent, path_w.as_ptr(), 0, KEY_READ, &mut hkey) };
        if status == ERROR_SUCCESS && !hkey.is_null() {
            Some(RegKey(hkey))
        } else {
            None
        }
    }

    /// Noms des sous-clefs, dans l'ordre du registre.
    fn subkeys(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        let mut index: u32 = 0;
        loop {
            let mut name = [0u16; 256];
            let mut len: u32 = name.len() as u32;
            let mut ft = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            // SAFETY : tampon de 256 unités, taille annoncée dans `len`.
            let status = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    name.as_mut_ptr(),
                    &mut len,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut ft,
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                return names;
            }
            if status != ERROR_SUCCESS {
                // ERROR_MORE_DATA (nom > 255 : impossible pour une clef) ou
                // erreur transitoire : on passe à la suivante, jamais de panique
                index += 1;
                continue;
            }
            names.push(String::from_utf16_lossy(&name[..len as usize]));
            index += 1;
        }
    }

    /// Valeur chaîne (`REG_SZ`/`REG_EXPAND_SZ`), NUL final rogné.
    fn string_value(&self, name: &str) -> Option<String> {
        let name_w = to_wide(name);
        let mut kind: REG_VALUE_TYPE = 0;
        let mut size: u32 = 0;
        // SAFETY : première passe, tailles seulement.
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                name_w.as_ptr(),
                std::ptr::null(),
                &mut kind,
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if status != ERROR_SUCCESS || size == 0 {
            return None;
        }
        let mut data = vec![0u8; size as usize];
        // SAFETY : tampon de `size` octets exactement.
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                name_w.as_ptr(),
                std::ptr::null(),
                &mut kind,
                data.as_mut_ptr(),
                &mut size,
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let text = String::from_utf16_lossy(&units);
        Some(text.trim_end_matches('\0').to_string())
    }

    /// Valeur `REG_DWORD`.
    fn dword_value(&self, name: &str) -> Option<u32> {
        let name_w = to_wide(name);
        let mut kind: REG_VALUE_TYPE = 0;
        let mut data = [0u8; 4];
        let mut size: u32 = 4;
        // SAFETY : tampon de 4 octets pour un DWORD.
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                name_w.as_ptr(),
                std::ptr::null(),
                &mut kind,
                data.as_mut_ptr(),
                &mut size,
            )
        };
        if status == ERROR_SUCCESS && size == 4 {
            Some(u32::from_le_bytes(data))
        } else {
            None
        }
    }
}

/// Capture normalisée du collecteur `windows.services` : lecture de
/// `HKLM\SYSTEM\CurrentControlSet\Services` (valeurs `Start`, `ObjectName`,
/// `ImagePath`). Seules les sous-clefs portant `Start` sont retenues.
pub fn collect_services_capture() -> Result<String, String> {
    let services = RegKey::open(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services")
        .ok_or_else(|| {
            "registre : HKLM\\SYSTEM\\CurrentControlSet\\Services illisible".to_string()
        })?;
    let mut out = String::new();
    let mut names = services.subkeys();
    names.sort();
    for name in names {
        // un nom de service avec espace ou saut de ligne casserait l'en-tête
        // INI : neutralisé (l'extracteur ignore les en-têtes avec espace)
        if name.trim().is_empty() || name.contains(char::is_whitespace) {
            continue;
        }
        let Some(key) = RegKey::open(
            HKEY_LOCAL_MACHINE,
            &format!("SYSTEM\\CurrentControlSet\\Services\\{name}"),
        ) else {
            continue;
        };
        let Some(start) = key.dword_value("Start") else {
            continue; // pas une entrée de service (pas de valeur Start)
        };
        let _ = writeln!(out, "[{name}]");
        let _ = writeln!(out, "start = {start}");
        if let Some(account) = key.string_value("ObjectName") {
            if !account.is_empty() {
                let _ = writeln!(out, "object_name = {}", clean(&account));
            }
        }
        if let Some(path) = key.string_value("ImagePath") {
            if !path.is_empty() {
                let _ = writeln!(out, "image_path = {}", clean(&path));
            }
        }
        out.push('\n');
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// ad.groups / ad.gpo_security — découverte du domaine
// ---------------------------------------------------------------------------

/// Contrôleur et nom du domaine joint, via `DsGetDcName`.
struct DcInfo {
    /// Nom du contrôleur, préfixe `\\` conservé (format attendu par NetXxx).
    dc_name: String,
    /// Nom du domaine (DNS ou NetBIOS selon la configuration).
    domain: String,
}

/// Découvre le contrôleur de domaine. Erreur propre si la machine n'est pas
/// jointe à un domaine (`ERROR_NO_SUCH_DOMAIN`, code 1355) ou si le
/// contrôleur est injoignable.
fn ds_dc_info() -> Result<DcInfo, String> {
    let mut info: *mut windows_sys::Win32::Networking::ActiveDirectory::DOMAIN_CONTROLLER_INFOW =
        std::ptr::null_mut();
    // SAFETY : appel documenté ; le tampon rendu est libéré par NetApiBufferFree.
    let status = unsafe {
        DsGetDcNameW(
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut info,
        )
    };
    if status != ERROR_SUCCESS || info.is_null() {
        return Err(format!(
            "machine non jointe à un domaine ou contrôleur injoignable (DsGetDcName : code {status})"
        ));
    }
    let _guard = NetBuffer(info as *mut u8);
    // SAFETY : le tampon contient un DOMAIN_CONTROLLER_INFOW valide ; les
    // champs sont des chaînes NUL-terminées.
    let (dc_name, domain) = unsafe {
        (
            pwstr_to_string((*info).DomainControllerName),
            pwstr_to_string((*info).DomainName),
        )
    };
    if domain.is_empty() {
        return Err("DsGetDcName : nom de domaine vide".to_string());
    }
    Ok(DcInfo { dc_name, domain })
}

/// Nom du domaine joint — utilisé par `ad.gpo_security` pour bâtir le chemin
/// SYSVOL. Erreur propre hors domaine.
pub fn joined_domain_name() -> Result<String, String> {
    ds_dc_info().map(|dc| dc.domain)
}

/// Capture normalisée du collecteur `ad.groups` : groupes globaux du domaine
/// (`NetGroupEnum` niveau 0 vers le contrôleur), membres
/// (`NetGroupGetUsers` niveau 0), SID par `LookupAccountName` vers le
/// contrôleur. Erreur propre hors domaine.
pub fn collect_ad_groups_capture() -> Result<String, String> {
    let dc = ds_dc_info()?;
    let server_w = to_wide(&dc.dc_name);
    let server_bare = dc.dc_name.trim_start_matches('\\').to_string();

    // énumération des groupes globaux du domaine
    let mut groups: Vec<String> = Vec::new();
    let mut resume: usize = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read: u32 = 0;
        let mut total: u32 = 0;
        // SAFETY : appel documenté ; tampon libéré par NetBuffer.
        let status = unsafe {
            NetGroupEnum(
                server_w.as_ptr(),
                0,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        let _guard = NetBuffer(buf);
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return Err(format!("NetGroupEnum vers {} : code {status}", dc.dc_name));
        }
        if !buf.is_null() && read > 0 {
            // SAFETY : `read` entrées GROUP_INFO_0 garanties par l'API.
            let entries =
                unsafe { std::slice::from_raw_parts(buf as *const GROUP_INFO_0, read as usize) };
            for e in entries {
                // SAFETY : chaîne NUL-terminée de l'API.
                let name = unsafe { pwstr_to_string(e.grpi0_name) };
                if !name.is_empty() {
                    groups.push(name);
                }
            }
        }
        if status != ERROR_MORE_DATA {
            break;
        }
    }
    groups.sort();
    groups.dedup();

    let mut out = String::from("[domain]\n");
    let _ = writeln!(out, "name = {}", clean(&dc.domain));
    out.push('\n');

    for group in &groups {
        let sid = lookup_account_sid(Some(&server_bare), &format!("{}\\{group}", dc.domain))
            .unwrap_or_else(|| "inconnu".to_string());
        let _ = writeln!(out, "[group {sid}]");
        let _ = writeln!(out, "name = {}", clean(group));
        for member in group_members(&server_w, group) {
            let _ = writeln!(out, "member = {}", clean(&member));
        }
        out.push('\n');
    }
    Ok(out)
}

/// Membres d'un groupe global (`NetGroupGetUsers` niveau 0). Un groupe
/// illisible rend une liste vide : la collecte continue.
fn group_members(server_w: &[u16], group: &str) -> Vec<String> {
    let group_w = to_wide(group);
    let mut members: Vec<String> = Vec::new();
    let mut resume: usize = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read: u32 = 0;
        let mut total: u32 = 0;
        // SAFETY : appel documenté ; tampon libéré par NetBuffer.
        let status = unsafe {
            NetGroupGetUsers(
                server_w.as_ptr(),
                group_w.as_ptr(),
                0,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            )
        };
        let _guard = NetBuffer(buf);
        if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
            return members;
        }
        if !buf.is_null() && read > 0 {
            // SAFETY : `read` entrées GROUP_USERS_INFO_0 garanties par l'API.
            let entries = unsafe {
                std::slice::from_raw_parts(buf as *const GROUP_USERS_INFO_0, read as usize)
            };
            for e in entries {
                // SAFETY : chaîne NUL-terminée de l'API.
                let name = unsafe { pwstr_to_string(e.grui0_name) };
                if !name.is_empty() {
                    members.push(name);
                }
            }
        }
        if status != ERROR_MORE_DATA {
            members.sort();
            members.dedup();
            return members;
        }
    }
}
