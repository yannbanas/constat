//! Harnais de charge de Constat : « est-ce que ça tient un vrai parc ? »
//!
//! Simule un parc paramétrable (défaut : 200 machines × 90 jours × une
//! collecte toutes les 6 h = 72 000 snapshots) contre un VRAI `RedbStore`
//! sur disque, puis mesure ce que coûtent les requêtes du produit sur le
//! magasin plein : `state --at`, `history`, `check`, export, vérification.
//!
//! Le chiffre central est celui de la promesse §3.3 de
//! CONSTAT-ARCHITECTURE.md : le ratio octets-stockés / octets-collectés sur
//! un parc qui ne bouge presque pas — c'est lui qui rend viable (ou non) une
//! rétention de trois ans.
//!
//! Tout est déterministe (PRNG splitmix64, graine fixe, horodatages simulés,
//! une seule clé de signature dérivée de la graine) : deux exécutions aux
//! mêmes paramètres produisent le même magasin, à l'octet près.
//!
//! Ce binaire vit dans un workspace indépendant (comme `fuzz/`) : il ne
//! modifie aucun crate du produit et n'entre pas dans son arbre de
//! dépendances.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;

use constat_model::{
    from_canonical_bytes, to_canonical_bytes, AssetId, Attribute, Blob, BlobHash, EntityId, Fact,
    Snapshot, Timestamp, Value,
};
use constat_store::{append_signed, export_store, JournalEntry, RedbStore, Signer, Store};

use constat_cli::coverage::{coverage_report_declared, DEFAULT_MAX_EXPECTED_GAP};
use constat_cli::eval::{build_inputs_with_gaps, evaluate_park};
use constat_cli::queries;
use constat_policy::{Assertion, AssertionId, AssetSelector, EntityPattern, Predicate};
use constat_time::Period;
use constat_verify::{verify_export, Export};

/// 2026-01-01T00:00:00.000Z — début simulé de la période de collecte.
const START_MS: i64 = 1_767_225_600_000;
const MS_PER_DAY: i64 = 86_400_000;

// ---------------------------------------------------------------------------
// Paramètres
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct Params {
    label: String,
    machines: usize,
    days: usize,
    per_day: usize,
    /// Pourcentage de machines qui changent UN fait par jour (dérive).
    drift_percent: f64,
    seed: u64,
    state_samples: usize,
}

fn usage() -> ! {
    eprintln!(
        "constat-bench — harnais de charge Constat\n\n\
         USAGE : constat-bench [OPTIONS]\n\n\
         OPTIONS :\n\
           --label <s>          nom du scénario (défaut : nominal)\n\
           --machines <n>       taille du parc (défaut : 200)\n\
           --days <n>           jours simulés (défaut : 90)\n\
           --per-day <n>        collectes par jour (défaut : 4, soit toutes les 6 h)\n\
           --drift <pct>        %% de machines changeant un fait par jour (défaut : 1.0)\n\
           --seed <n>           graine du PRNG (défaut : 42)\n\
           --state-samples <n>  machines échantillonnées pour `state --at` (défaut : 20)\n\
           --out <dir>          répertoire des résultats JSON (défaut : results)\n\
           --workdir <dir>      répertoire de travail du magasin (défaut : temp système)\n\
           --keep               ne pas supprimer le répertoire de travail à la fin\n\
           --quick              préréglage d'itération : 20 machines × 14 jours"
    );
    std::process::exit(2)
}

struct Args {
    params: Params,
    out: PathBuf,
    workdir: Option<PathBuf>,
    keep: bool,
}

fn parse_args() -> Args {
    let mut params = Params {
        label: "nominal".to_string(),
        machines: 200,
        days: 90,
        per_day: 4,
        drift_percent: 1.0,
        seed: 42,
        state_samples: 20,
    };
    let mut out = PathBuf::from("results");
    let mut workdir = None;
    let mut keep = false;

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let val = |i: &mut usize| -> String {
        *i += 1;
        argv.get(*i).cloned().unwrap_or_else(|| usage())
    };
    while i < argv.len() {
        match argv[i].as_str() {
            "--label" => params.label = val(&mut i),
            "--machines" => params.machines = val(&mut i).parse().unwrap_or_else(|_| usage()),
            "--days" => params.days = val(&mut i).parse().unwrap_or_else(|_| usage()),
            "--per-day" => params.per_day = val(&mut i).parse().unwrap_or_else(|_| usage()),
            "--drift" => params.drift_percent = val(&mut i).parse().unwrap_or_else(|_| usage()),
            "--seed" => params.seed = val(&mut i).parse().unwrap_or_else(|_| usage()),
            "--state-samples" => {
                params.state_samples = val(&mut i).parse().unwrap_or_else(|_| usage())
            }
            "--out" => out = PathBuf::from(val(&mut i)),
            "--workdir" => workdir = Some(PathBuf::from(val(&mut i))),
            "--keep" => keep = true,
            "--quick" => {
                params.machines = 20;
                params.days = 14;
                if params.label == "nominal" {
                    params.label = "quick".to_string();
                }
            }
            "--help" | "-h" => usage(),
            other => {
                eprintln!("option inconnue : {other}");
                usage()
            }
        }
        i += 1;
    }
    Args {
        params,
        out,
        workdir,
        keep,
    }
}

// ---------------------------------------------------------------------------
// PRNG déterministe (splitmix64) — aucune dépendance, graine fixe
// ---------------------------------------------------------------------------

struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Self {
        Prng(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

// ---------------------------------------------------------------------------
// Profil de données : ~153 faits par machine, répartis sur 6 collecteurs
// réels (inventory, accounts, sshd, packages ×110, ports, kernel_params),
// avec des artefacts bruts de taille réaliste (texte de configuration).
// ---------------------------------------------------------------------------

const PKG_COUNT: usize = 110;
const PKG_WORDS: [&str; 20] = [
    "openssl", "curl", "systemd", "python3", "linux-image", "openssh", "zlib1g", "libc6", "bash",
    "coreutils", "nginx", "postgresql", "rsyslog", "chrony", "sudo", "cron", "logrotate", "vim",
    "tar", "gnupg",
];

fn pkg_name(i: usize) -> String {
    format!("{}-{:03}", PKG_WORDS[i % PKG_WORDS.len()], i)
}

/// État persistant d'une machine simulée : seul l'état des paquets dérive.
struct Machine {
    name: String,
    /// Version mineure de chaque paquet — la dérive incrémente l'une d'elles.
    pkg_ver: Vec<u32>,
}

impl Machine {
    fn new(index: usize, prng: &mut Prng) -> Self {
        let name = format!("srv-{index:03}");
        // Bruit par machine : les parcs réels ne sont jamais parfaitement
        // homogènes — chaque machine a donc son propre blob `packages`.
        let pkg_ver = (0..PKG_COUNT).map(|_| 100 + (prng.below(4) as u32)).collect();
        Machine { name, pkg_ver }
    }
}

/// Un blob prêt à pousser, avec la taille de son encodage canonique — la
/// taille « collectée » qu'un magasin naïf écrirait à chaque collecte.
struct CachedBlob {
    blob: Blob,
    canonical_len: u64,
}

fn cache(blob: Blob) -> CachedBlob {
    let canonical_len = to_canonical_bytes(&blob)
        .expect("encodage canonique du blob")
        .len() as u64;
    CachedBlob {
        blob,
        canonical_len,
    }
}

fn inventory_blob(name: &str) -> CachedBlob {
    let raw = format!(
        "hostname: {name}\nos: linux\ndistribution: debian-12\nkernel: 6.1.0-30-amd64\n\
         domain: interne\ntags: production\nsite: dc-lyon\n"
    );
    let e = format!("asset:{name}");
    let facts = vec![
        Fact::new(e.as_str(), "asset.os", "linux"),
        Fact::new(
            e.as_str(),
            "asset.tag",
            Value::List(vec![Value::Text("production".into())]),
        ),
        Fact::new(e.as_str(), "asset.domain", "interne"),
    ];
    cache(Blob::new("linux.inventory", raw.into_bytes(), facts))
}

fn accounts_blob(name: &str) -> CachedBlob {
    let users: Vec<(String, bool, &str)> = vec![
        ("root".to_string(), true, "/bin/bash"),
        ("admin".to_string(), true, "/bin/bash"),
        ("svc-backup".to_string(), false, "/usr/sbin/nologin"),
    ]
    .into_iter()
    .chain((0..7).map(|i| (format!("user{i:02}"), false, "/bin/bash")))
    .collect();
    // Le brut ressemble à /etc/passwd + /etc/group, expurgé. Le nom d'hôte y
    // figure : sur un vrai parc, ces fichiers diffèrent d'une machine à
    // l'autre (uid, historique) — pas de déduplication inter-machines ici.
    let mut raw = format!("# extrait expurgé — {name}\n");
    for (i, (u, _, shell)) in users.iter().enumerate() {
        raw.push_str(&format!("{u}:x:{}:{}::/home/{u}:{shell}\n", 1000 + i, 1000 + i));
    }
    raw.push_str("sudo:x:27:root,admin\n");
    let mut facts = Vec::with_capacity(users.len() * 2);
    for (u, privileged, shell) in &users {
        let e = format!("user:{u}");
        facts.push(Fact::new(e.as_str(), "user.privileged", *privileged));
        facts.push(Fact::new(e.as_str(), "user.shell", *shell));
    }
    cache(Blob::new("linux.accounts", raw.into_bytes(), facts))
}

fn sshd_blob() -> CachedBlob {
    // Identique sur tout le parc : une configuration déployée par gestionnaire
    // de configuration. La déduplication inter-machines est ici réaliste.
    let raw = "# sshd_config — géré par ansible, ne pas éditer\n\
               Port 22\nPermitRootLogin no\nPasswordAuthentication no\n\
               PubkeyAuthentication yes\nX11Forwarding no\nMaxAuthTries 4\n\
               ClientAliveInterval 300\nClientAliveCountMax 2\n\
               AllowTcpForwarding no\nLogLevel VERBOSE\nSubsystem sftp internal-sftp\n"
        .to_string();
    let e = "service:sshd";
    let facts = vec![
        Fact::new(e, "sshd.Port", 22i64),
        Fact::new(e, "sshd.PermitRootLogin", "no"),
        Fact::new(e, "sshd.PasswordAuthentication", "no"),
        Fact::new(e, "sshd.PubkeyAuthentication", "yes"),
        Fact::new(e, "sshd.X11Forwarding", "no"),
        Fact::new(e, "sshd.MaxAuthTries", 4i64),
        Fact::new(e, "sshd.ClientAliveInterval", 300i64),
        Fact::new(e, "sshd.AllowTcpForwarding", "no"),
    ];
    cache(Blob::new("linux.sshd", raw.into_bytes(), facts))
}

fn ports_blob() -> CachedBlob {
    let ports: [(i64, &str); 6] = [
        (22, "sshd"),
        (9100, "node_exporter"),
        (5432, "postgres"),
        (443, "nginx"),
        (123, "chronyd"),
        (514, "rsyslogd"),
    ];
    let mut raw = String::from("Netid State  Local Address:Port Process\n");
    let mut facts = Vec::with_capacity(ports.len());
    for (p, proc_name) in ports {
        raw.push_str(&format!("tcp   LISTEN 0.0.0.0:{p}  users:((\"{proc_name}\"))\n"));
        facts.push(Fact::new(
            format!("port:{p}").as_str(),
            "port.process",
            proc_name,
        ));
    }
    cache(Blob::new("linux.ports", raw.into_bytes(), facts))
}

fn kernel_blob() -> CachedBlob {
    let params: [(&str, &str); 6] = [
        ("net.ipv4.ip_forward", "0"),
        ("net.ipv4.conf.all.rp_filter", "1"),
        ("kernel.randomize_va_space", "2"),
        ("net.ipv4.tcp_syncookies", "1"),
        ("fs.protected_symlinks", "1"),
        ("kernel.kptr_restrict", "2"),
    ];
    let mut raw = String::new();
    let mut facts = Vec::with_capacity(params.len());
    for (k, v) in params {
        raw.push_str(&format!("{k} = {v}\n"));
        facts.push(Fact::new(format!("sysctl:{k}").as_str(), "sysctl.value", v));
    }
    cache(Blob::new("linux.kernel_params", raw.into_bytes(), facts))
}

fn packages_blob(pkg_ver: &[u32]) -> CachedBlob {
    let mut raw = String::with_capacity(PKG_COUNT * 48);
    raw.push_str("Desired=Unknown/Install ; Status=Not/Inst\n||/ Name Version Architecture\n");
    let mut facts = Vec::with_capacity(PKG_COUNT);
    for (i, ver) in pkg_ver.iter().enumerate() {
        let name = pkg_name(i);
        let version = format!("2.{}.{}-deb12u1", i % 10, ver);
        raw.push_str(&format!("ii  {name}  {version}  amd64\n"));
        facts.push(Fact::new(
            format!("pkg:{name}").as_str(),
            "pkg.version",
            version.as_str(),
        ));
    }
    cache(Blob::new("linux.packages", raw.into_bytes(), facts))
}

/// Les 6 blobs d'une machine, dans l'ordre des collecteurs.
/// Seul `packages` (index 5) est reconstruit quand la machine dérive.
fn build_all(m: &Machine, shared: &SharedBlobs) -> Vec<CachedBlob> {
    vec![
        inventory_blob(&m.name),
        accounts_blob(&m.name),
        cache(shared.sshd.blob.clone()),
        cache(shared.ports.blob.clone()),
        cache(shared.kernel.blob.clone()),
        packages_blob(&m.pkg_ver),
    ]
}

struct SharedBlobs {
    sshd: CachedBlob,
    ports: CachedBlob,
    kernel: CachedBlob,
}

// ---------------------------------------------------------------------------
// Mémoire de pointe (Windows uniquement — sinon omise, et dite omise)
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn mem_info() -> Option<(u64, u64)> {
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // Lecture des compteurs mémoire du processus courant via l'API documentée
    // de Windows ; aucun pointeur ne survit à l'appel.
    unsafe {
        let mut c: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) != 0 {
            Some((c.WorkingSetSize as u64, c.PeakWorkingSetSize as u64))
        } else {
            None
        }
    }
}

#[cfg(not(windows))]
fn mem_info() -> Option<(u64, u64)> {
    None
}

fn mem_mib() -> Option<MemSample> {
    mem_info().map(|(ws, peak)| MemSample {
        working_set_mib: ws as f64 / (1024.0 * 1024.0),
        peak_working_set_mib: peak as f64 / (1024.0 * 1024.0),
    })
}

#[derive(Debug, Clone, Serialize)]
struct MemSample {
    working_set_mib: f64,
    peak_working_set_mib: f64,
}

// ---------------------------------------------------------------------------
// Résultats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct Checkpoint {
    day: usize,
    store_file_bytes: u64,
    collected_bytes: u64,
    ratio_stored_over_collected: f64,
    blob_count: u64,
    snapshot_count: u64,
    entry_count: u64,
}

#[derive(Debug, Clone, Serialize)]
struct IngestReport {
    total_snapshots: u64,
    wall_seconds: f64,
    snapshots_per_second: f64,
    /// Répartition du temps d'ingestion (mesure directe des appels).
    put_blob_seconds: f64,
    put_snapshot_seconds: f64,
    append_entry_seconds: f64,
    generation_seconds: f64,
    /// Micro-mesures séparées (moyennes), pour estimer la part du hachage et
    /// de la signature à l'intérieur des appels ci-dessus.
    blob_hash_micros_avg: f64,
    sign_entry_micros_avg: f64,
    checkpoints: Vec<Checkpoint>,
    mem_after: Option<MemSample>,
}

#[derive(Debug, Clone, Serialize)]
struct StateQueryReport {
    samples: usize,
    median_ms: f64,
    min_ms: f64,
    max_ms: f64,
    facts_per_state: usize,
}

#[derive(Debug, Clone, Serialize)]
struct HistoryReport {
    entity: String,
    attribute: String,
    wall_seconds: f64,
    changes: usize,
    mem_after: Option<MemSample>,
}

#[derive(Debug, Clone, Serialize)]
struct CheckReport {
    wall_seconds: f64,
    observations_seconds: f64,
    observations_count: usize,
    build_inputs_seconds: f64,
    evaluate_seconds: f64,
    verdict: String,
    violations: usize,
    mem_after: Option<MemSample>,
}

#[derive(Debug, Clone, Serialize)]
struct ExportReport {
    wall_seconds: f64,
    dir_bytes: u64,
    file_count: u64,
    load_seconds: f64,
    verify_seconds: f64,
    verify_root_hex: String,
    verified_entries: usize,
    verified_snapshots: usize,
    verified_blobs: usize,
    mem_after: Option<MemSample>,
}

#[derive(Debug, Clone, Serialize)]
struct Report {
    params: Params,
    started_at_utc_ms: i64,
    ingest: IngestReport,
    /// Extrapolation LINÉAIRE à 3 ans (1095 jours), à partir de la croissance
    /// mesurée sur la dernière tranche de jours — c'est une extrapolation,
    /// pas une mesure.
    store_bytes_extrapolated_3y_linear: u64,
    state_query: StateQueryReport,
    history: HistoryReport,
    check: CheckReport,
    export: ExportReport,
    peak_working_set_mib: Option<f64>,
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

fn dir_stats(dir: &Path) -> (u64, u64) {
    let mut bytes = 0u64;
    let mut files = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(md) = e.metadata() {
                bytes += md.len();
                files += 1;
            }
        }
    }
    (bytes, files)
}

fn secs(d: Duration) -> f64 {
    d.as_secs_f64()
}

fn mib(b: u64) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}

/// Charge un export au format normatif de `constat-verify` (FORMAT.md) —
/// le binaire `constat-verify` fait la même chose ; sa bibliothèque est pure,
/// le chargement est donc réimplémenté ici (une quarantaine de lignes).
fn load_export(dir: &Path) -> Export {
    let pubkey_bytes = fs::read(dir.join("pubkey.bin")).expect("pubkey.bin");
    let public_key: [u8; 32] = pubkey_bytes.as_slice().try_into().expect("clé de 32 octets");

    let mut entries = Vec::new();
    let mut i = 0usize;
    loop {
        let p = dir.join(format!("{i}.cbor"));
        if !p.exists() {
            break;
        }
        let bytes = fs::read(&p).expect("lecture d'entrée");
        let entry: JournalEntry = from_canonical_bytes(&bytes).expect("décodage d'entrée");
        entries.push(entry);
        i += 1;
    }

    let mut snapshots = BTreeMap::new();
    for e in fs::read_dir(dir.join("snapshots")).expect("snapshots/").flatten() {
        let p = e.path();
        let stem = p.file_stem().and_then(|s| s.to_str()).expect("nom hexadécimal");
        let hash = BlobHash::from_hex(stem).expect("empreinte du nom de fichier");
        let bytes = fs::read(&p).expect("lecture de snapshot");
        let snap: Snapshot = from_canonical_bytes(&bytes).expect("décodage de snapshot");
        snapshots.insert(hash, snap);
    }

    let mut blobs = BTreeMap::new();
    for e in fs::read_dir(dir.join("blobs")).expect("blobs/").flatten() {
        let p = e.path();
        let stem = p.file_stem().and_then(|s| s.to_str()).expect("nom hexadécimal");
        let hash = BlobHash::from_hex(stem).expect("empreinte du nom de fichier");
        let bytes = fs::read(&p).expect("lecture de blob");
        let blob: Blob = from_canonical_bytes(&bytes).expect("décodage de blob");
        blobs.insert(hash, blob);
    }

    Export {
        entries,
        snapshots,
        blobs,
        public_key,
    }
}

// ---------------------------------------------------------------------------
// Le scénario
// ---------------------------------------------------------------------------

fn main() {
    let args = parse_args();
    let p = &args.params;
    let interval_ms = MS_PER_DAY / p.per_day as i64;
    let total_ticks = p.days * p.per_day;

    println!(
        "=== constat-bench « {} » : {} machines × {} jours × {} collectes/jour \
         (dérive {} %/jour, graine {}) ===",
        p.label, p.machines, p.days, p.per_day, p.drift_percent, p.seed
    );

    // Répertoire de travail : magasin + export, supprimé à la fin sauf --keep.
    let workdir = args.workdir.clone().unwrap_or_else(|| {
        std::env::temp_dir().join(format!("constat-bench-{}", p.label))
    });
    if workdir.exists() {
        fs::remove_dir_all(&workdir).expect("nettoyage du répertoire de travail");
    }
    fs::create_dir_all(&workdir).expect("création du répertoire de travail");
    let store_path = workdir.join("park.redb");

    let mut store = RedbStore::open(&store_path).expect("ouverture du magasin");
    // Une seule clé de signature, dérivée de la graine : déterministe.
    let mut key_seed = [0u8; 32];
    let mut kp = Prng::new(p.seed ^ 0x5EED_C0DE);
    for chunk in key_seed.chunks_mut(8) {
        chunk.copy_from_slice(&kp.next().to_le_bytes()[..chunk.len()]);
    }
    let signer = Signer::from_bytes(&key_seed);

    // --- Génération initiale du parc -------------------------------------
    let mut prng = Prng::new(p.seed);
    let t_gen0 = Instant::now();
    let shared = SharedBlobs {
        sshd: sshd_blob(),
        ports: ports_blob(),
        kernel: kernel_blob(),
    };
    let mut machines: Vec<Machine> = (0..p.machines).map(|i| Machine::new(i, &mut prng)).collect();
    let mut blobs_by_machine: Vec<Vec<CachedBlob>> =
        machines.iter().map(|m| build_all(m, &shared)).collect();
    let mut generation = t_gen0.elapsed();

    let facts_per_machine: usize = blobs_by_machine[0].iter().map(|c| c.blob.facts.len()).sum();
    println!(
        "profil : {} faits/machine sur {} collecteurs, {:.1} Kio collectés/machine/collecte",
        facts_per_machine,
        blobs_by_machine[0].len(),
        blobs_by_machine[0].iter().map(|c| c.canonical_len).sum::<u64>() as f64 / 1024.0
    );

    // --- Ingestion ---------------------------------------------------------
    let drift_per_day =
        ((p.machines as f64) * p.drift_percent / 100.0).round().max(if p.drift_percent > 0.0 {
            1.0
        } else {
            0.0
        }) as usize;

    let mut collected_bytes = 0u64;
    let mut put_blob_time = Duration::ZERO;
    let mut put_snapshot_time = Duration::ZERO;
    let mut append_time = Duration::ZERO;
    let mut checkpoints = Vec::new();
    // Première dérive observée : l'entité dont on demandera l'historique.
    let mut first_drift: Option<(usize, usize)> = None;

    let t_ingest = Instant::now();
    for day in 0..p.days {
        // Dérive : `drift_per_day` machines changent UN fait (une version de
        // paquet est incrémentée) — le reste du parc ne bouge pas.
        if day > 0 && drift_per_day > 0 {
            let t = Instant::now();
            for _ in 0..drift_per_day {
                let mi = prng.below(p.machines as u64) as usize;
                let pi = prng.below(PKG_COUNT as u64) as usize;
                machines[mi].pkg_ver[pi] += 1;
                blobs_by_machine[mi][5] = packages_blob(&machines[mi].pkg_ver);
                first_drift.get_or_insert((mi, pi));
            }
            generation += t.elapsed();
        }

        for tick in 0..p.per_day {
            let at = Timestamp(START_MS + ((day * p.per_day + tick) as i64) * interval_ms);
            let mut tick_snapshots = Vec::with_capacity(p.machines);

            for (mi, m) in machines.iter().enumerate() {
                let mut map = BTreeMap::new();
                for cached in &blobs_by_machine[mi] {
                    let t = Instant::now();
                    let h = store.put_blob(&cached.blob).expect("put_blob");
                    put_blob_time += t.elapsed();
                    collected_bytes += cached.canonical_len;
                    map.insert(cached.blob.collector.clone(), h);
                }
                let snapshot = Snapshot::new(m.name.as_str(), at, map);
                let t = Instant::now();
                let sh = store.put_snapshot(&snapshot).expect("put_snapshot");
                put_snapshot_time += t.elapsed();
                tick_snapshots.push(sh);
            }

            // Une entrée de journal par vague de collecte (le serveur signe
            // la vague entière) — 4 entrées de 200 empreintes par jour.
            let t = Instant::now();
            append_signed(&mut store, &signer, tick_snapshots, at).expect("append_signed");
            append_time += t.elapsed();
        }

        let d = day + 1;
        if d % 30 == 0 || d == p.days {
            let file_bytes = fs::metadata(&store_path).map(|m| m.len()).unwrap_or(0);
            checkpoints.push(Checkpoint {
                day: d,
                store_file_bytes: file_bytes,
                collected_bytes,
                ratio_stored_over_collected: file_bytes as f64 / collected_bytes.max(1) as f64,
                blob_count: store.blob_count().expect("blob_count"),
                snapshot_count: store.snapshot_count().expect("snapshot_count"),
                entry_count: store.entry_count().expect("entry_count"),
            });
            println!(
                "  jour {d:3} : magasin {:8.1} Mio | collecté {:9.1} Mio | ratio {:.4} | \
                 {} blobs, {} snapshots, {} entrées",
                mib(checkpoints.last().unwrap().store_file_bytes),
                mib(collected_bytes),
                checkpoints.last().unwrap().ratio_stored_over_collected,
                checkpoints.last().unwrap().blob_count,
                checkpoints.last().unwrap().snapshot_count,
                checkpoints.last().unwrap().entry_count,
            );
        }
    }
    let ingest_wall = t_ingest.elapsed();
    let total_snapshots = (p.machines * total_ticks) as u64;

    // Micro-mesures : hachage d'un blob et signature d'une entrée, isolés.
    let hash_iters = 2_000usize;
    let t = Instant::now();
    for i in 0..hash_iters {
        let c = &blobs_by_machine[i % p.machines][i % 6];
        std::hint::black_box(constat_model::blob_hash(&c.blob).expect("blob_hash"));
    }
    let blob_hash_micros = t.elapsed().as_secs_f64() * 1e6 / hash_iters as f64;

    let sign_iters = 200usize;
    let fake: Vec<BlobHash> = (0..p.machines).map(|i| BlobHash([i as u8; 32])).collect();
    let t = Instant::now();
    for _ in 0..sign_iters {
        std::hint::black_box(
            signer
                .sign_entry(None, fake.clone(), Timestamp(START_MS))
                .expect("sign_entry"),
        );
    }
    let sign_micros = t.elapsed().as_secs_f64() * 1e6 / sign_iters as f64;

    let ingest = IngestReport {
        total_snapshots,
        wall_seconds: secs(ingest_wall),
        snapshots_per_second: total_snapshots as f64 / secs(ingest_wall),
        put_blob_seconds: secs(put_blob_time),
        put_snapshot_seconds: secs(put_snapshot_time),
        append_entry_seconds: secs(append_time),
        generation_seconds: secs(generation),
        blob_hash_micros_avg: blob_hash_micros,
        sign_entry_micros_avg: sign_micros,
        checkpoints: checkpoints.clone(),
        mem_after: mem_mib(),
    };
    println!(
        "ingestion : {} snapshots en {:.1} s → {:.0} snapshots/s \
         (put_blob {:.1} s, put_snapshot {:.1} s, append {:.1} s, génération {:.1} s)",
        total_snapshots,
        ingest.wall_seconds,
        ingest.snapshots_per_second,
        ingest.put_blob_seconds,
        ingest.put_snapshot_seconds,
        ingest.append_entry_seconds,
        ingest.generation_seconds,
    );
    println!(
        "micro-mesures : hachage de blob {:.0} µs, signature d'entrée {:.0} µs",
        blob_hash_micros, sign_micros
    );

    // Extrapolation linéaire à 3 ans, sur la croissance de la dernière tranche.
    let extrapolated_3y = {
        let last = checkpoints.last().expect("au moins un point de contrôle");
        let (base_day, base_bytes) = if checkpoints.len() >= 2 {
            let prev = &checkpoints[checkpoints.len() - 2];
            (prev.day, prev.store_file_bytes)
        } else {
            (0, 0)
        };
        let per_day =
            (last.store_file_bytes.saturating_sub(base_bytes)) as f64 / (last.day - base_day) as f64;
        (last.store_file_bytes as f64 + per_day * (1095 - last.day) as f64) as u64
    };
    println!(
        "extrapolation LINÉAIRE 3 ans (1095 j) : {:.1} Mio — c'est une extrapolation, pas une mesure",
        mib(extrapolated_3y)
    );

    // --- Requêtes sur le magasin plein ------------------------------------
    let store_ref: &dyn Store = &store;

    // `state --at` : médiane sur N machines, à mi-période.
    let mid = Timestamp(START_MS + (total_ticks as i64 / 2) * interval_ms);
    let n = p.state_samples.min(p.machines);
    let mut durations = Vec::with_capacity(n);
    let mut facts_per_state = 0usize;
    for k in 0..n {
        let idx = k * p.machines / n;
        let asset = AssetId(machines[idx].name.clone());
        let t = Instant::now();
        let view = queries::state_at(store_ref, &asset, mid)
            .expect("state_at")
            .expect("un état doit exister à mi-période");
        durations.push(t.elapsed().as_secs_f64() * 1000.0);
        facts_per_state = view.facts.len();
    }
    durations.sort_by(|a, b| a.partial_cmp(b).expect("durées comparables"));
    let state_query = StateQueryReport {
        samples: n,
        median_ms: durations[n / 2],
        min_ms: durations[0],
        max_ms: durations[n - 1],
        facts_per_state,
    };
    println!(
        "state --at (mi-période, {} machines) : médiane {:.0} ms (min {:.0}, max {:.0}), {} faits/état",
        n, state_query.median_ms, state_query.min_ms, state_query.max_ms, facts_per_state
    );

    // `history` : l'entité qui a réellement changé (première dérive), ou un
    // paquet arbitraire si le parc est figé (aucun changement à trouver).
    let (hist_entity, hist_attr) = match first_drift {
        Some((_, pi)) => (format!("pkg:{}", pkg_name(pi)), "pkg.version".to_string()),
        None => (format!("pkg:{}", pkg_name(0)), "pkg.version".to_string()),
    };
    let entity = EntityId(hist_entity.clone());
    let attr = Attribute(hist_attr.clone());
    let t = Instant::now();
    let hist = queries::history(store_ref, &entity, &attr, None).expect("history");
    let history = HistoryReport {
        entity: hist_entity,
        attribute: hist_attr,
        wall_seconds: secs(t.elapsed()),
        changes: hist.changes.len(),
        mem_after: mem_mib(),
    };
    println!(
        "history {} {} : {:.1} s, {} changements",
        history.entity, history.attribute, history.wall_seconds, history.changes
    );

    // `check` : une assertion simple sur tout le parc et toute la période,
    // assemblée exactement comme `constat check` (commands::evaluate_all).
    let assertion = Assertion {
        id: AssertionId("SSH-ROOT".to_string()),
        title: "la connexion root en SSH est désactivée".to_string(),
        scope: AssetSelector {
            os: Some("linux".to_string()),
            tag: None,
            domain: None,
        },
        predicate: Predicate::Never {
            entity: EntityPattern::Glob("service:sshd".to_string()),
            attr: Attribute("sshd.PermitRootLogin".to_string()),
            equals: Value::Text("yes".to_string()),
        },
        exceptions: Vec::new(),
    };
    let period = Period {
        from: Timestamp(START_MS),
        to: Timestamp(START_MS + (total_ticks as i64 - 1) * interval_ms),
    };
    let t_check = Instant::now();
    let t = Instant::now();
    let obs = queries::observations(store_ref).expect("observations");
    let observations_seconds = secs(t.elapsed());
    let observations_count = obs.len();
    let snap_times: Vec<(AssetId, Timestamp)> = queries::snapshots(store_ref)
        .expect("snapshots")
        .iter()
        .map(|(_, s)| (s.asset.clone(), s.at))
        .collect();
    let purge_gaps = queries::purge_gaps(store_ref).expect("purge_gaps");
    let t = Instant::now();
    let inputs = build_inputs_with_gaps(&obs, &snap_times, &purge_gaps, period, DEFAULT_MAX_EXPECTED_GAP)
        .expect("build_inputs");
    let build_inputs_seconds = secs(t.elapsed());
    let times: Vec<Timestamp> = snap_times.iter().map(|(_, t)| *t).collect();
    let park_coverage = coverage_report_declared(&times, &purge_gaps, period, DEFAULT_MAX_EXPECTED_GAP)
        .expect("couverture de parc");
    let t = Instant::now();
    let evaluation = evaluate_park(&assertion, &inputs, park_coverage).expect("evaluate_park");
    let evaluate_seconds = secs(t.elapsed());
    let check = CheckReport {
        wall_seconds: secs(t_check.elapsed()),
        observations_seconds,
        observations_count,
        build_inputs_seconds,
        evaluate_seconds,
        verdict: format!("{:?}", evaluation.verdict),
        violations: evaluation.violations.len(),
        mem_after: mem_mib(),
    };
    println!(
        "check SSH-ROOT (parc entier, période entière) : {:.1} s au total \
         (observations {:.1} s — {} observations, préparation {:.1} s, évaluation {:.1} s) → {} \
         ({} violations)",
        check.wall_seconds,
        check.observations_seconds,
        check.observations_count,
        check.build_inputs_seconds,
        check.evaluate_seconds,
        check.verdict,
        check.violations,
    );
    drop(obs);
    drop(inputs);

    // --- Export + vérification autonome -----------------------------------
    let export_dir = workdir.join("export");
    let t = Instant::now();
    export_store(&store, &export_dir, &signer.verifying_key()).expect("export_store");
    let export_seconds = secs(t.elapsed());
    let (dir_bytes, file_count) = dir_stats(&export_dir);

    let t = Instant::now();
    let export = load_export(&export_dir);
    let load_seconds = secs(t.elapsed());
    let t = Instant::now();
    let verified = verify_export(&export).expect("verify_export doit réussir");
    let verify_seconds = secs(t.elapsed());
    assert_eq!(
        Some(verified.root),
        store.root().expect("racine du magasin"),
        "la racine vérifiée doit être celle du magasin"
    );
    let export_report = ExportReport {
        wall_seconds: export_seconds,
        dir_bytes,
        file_count,
        load_seconds,
        verify_seconds,
        verify_root_hex: verified.root.to_hex(),
        verified_entries: verified.entry_count,
        verified_snapshots: verified.snapshot_count,
        verified_blobs: verified.blob_count,
        mem_after: mem_mib(),
    };
    println!(
        "export : {:.1} s, {:.1} Mio, {} fichiers | chargement {:.1} s | verify_export {:.1} s \
         (racine {})",
        export_report.wall_seconds,
        mib(dir_bytes),
        file_count,
        load_seconds,
        verify_seconds,
        verified.root,
    );

    let peak = mem_mib().map(|m| m.peak_working_set_mib);
    if let Some(peak) = peak {
        println!("mémoire de pointe du processus : {peak:.0} Mio");
    } else {
        println!("mémoire de pointe : non mesurée sur cette plateforme (omise)");
    }

    // --- Rapport JSON ------------------------------------------------------
    let report = Report {
        params: p.clone(),
        started_at_utc_ms: START_MS,
        ingest,
        store_bytes_extrapolated_3y_linear: extrapolated_3y,
        state_query,
        history,
        check,
        export: export_report,
        peak_working_set_mib: peak,
    };
    fs::create_dir_all(&args.out).expect("création du répertoire de résultats");
    let out_path = args.out.join(format!("{}.json", p.label));
    fs::write(
        &out_path,
        serde_json::to_string_pretty(&report).expect("sérialisation JSON"),
    )
    .expect("écriture du rapport");
    println!("rapport écrit : {}", out_path.display());

    // --- Nettoyage ---------------------------------------------------------
    drop(export);
    drop(store);
    if args.keep {
        println!("répertoire de travail conservé : {}", workdir.display());
    } else if let Err(e) = fs::remove_dir_all(&workdir) {
        eprintln!(
            "avertissement : nettoyage incomplet de {} : {e}",
            workdir.display()
        );
    }
}
