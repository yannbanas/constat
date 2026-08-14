//! `constat-agent install` — installation de la collecte planifiée.
//!
//! **Pas de démon maison** : l'agent s'appuie sur le planificateur du
//! système — systemd sur Linux, le Planificateur de tâches sur Windows.
//! C'est le choix honnête et robuste : superviser un processus qui dort est
//! le métier du système, pas celui d'un agent de collecte, et un
//! `run --once` périodique ne laisse aucun processus résident sur la
//! machine auditée.
//!
//! La commande **écrit les fichiers demandés, et rien d'autre** : elle
//! n'exécute ni `systemctl` ni `schtasks` — les commandes à lancer sont
//! affichées, la décision d'activer reste à l'opérateur. Avec `--print`,
//! rien n'est écrit du tout.
//!
//! La gigue du mode `--every` a son équivalent ici : `RandomizedDelaySec`
//! côté systemd, `<RandomDelay>` côté Planificateur de tâches — même
//! intention, étaler les collectes d'un parc au lieu de les faire tomber à
//! la même seconde.

use constat_model::DurationMs;

use crate::push::PushConfig;

/// Système cible de l'installation.
///
/// Par défaut le système courant ; explicitable pour préparer depuis un
/// poste d'administration les fichiers d'un parc hétérogène — la génération
/// est du texte pur, elle fonctionne partout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum InstallTarget {
    /// Paire d'unités systemd : service `oneshot` + timer.
    Linux,
    /// Tâche planifiée (XML pour `schtasks /create /xml`).
    Windows,
}

impl InstallTarget {
    /// Le système sur lequel ce binaire tourne.
    pub fn current() -> Self {
        if cfg!(windows) {
            InstallTarget::Windows
        } else {
            InstallTarget::Linux
        }
    }

    /// Chemin par défaut du magasin pour une installation système.
    pub fn default_store(self) -> &'static str {
        match self {
            InstallTarget::Linux => "/var/lib/constat/constat.redb",
            InstallTarget::Windows => r"C:\ProgramData\Constat\constat.redb",
        }
    }

    /// Répertoire par défaut des clés pour une installation système.
    pub fn default_keys(self) -> &'static str {
        match self {
            InstallTarget::Linux => "/var/lib/constat/agent.keys",
            InstallTarget::Windows => r"C:\ProgramData\Constat\agent.keys",
        }
    }

    /// Chemin conventionnel du binaire sur la machine cible — utilisé quand
    /// on génère pour un **autre** système que celui-ci : le chemin de
    /// l'exécutable courant n'y aurait aucun sens.
    pub fn default_exe(self) -> &'static str {
        match self {
            InstallTarget::Linux => "/usr/local/bin/constat-agent",
            InstallTarget::Windows => r"C:\Program Files\Constat\constat-agent.exe",
        }
    }
}

/// Nom du fichier de service systemd.
pub const SERVICE_UNIT: &str = "constat-agent.service";
/// Nom du fichier de timer systemd.
pub const TIMER_UNIT: &str = "constat-agent.timer";
/// Nom de la tâche planifiée Windows.
pub const TASK_NAME: &str = "Constat Agent";

/// Ce que l'installation doit planifier. Les chemins sont des chaînes :
/// ils décrivent la machine **cible**, pas forcément celle qui génère
/// (préparer des unités Linux depuis un poste Windows est légitime).
#[derive(Debug, Clone)]
pub struct InstallOptions {
    /// Intervalle entre deux collectes.
    pub every: DurationMs,
    /// Chemin du binaire tel qu'il sera invoqué par le planificateur.
    pub exe: String,
    /// Chemin du magasin local (chemin absolu recommandé : le planificateur
    /// n'exécute pas depuis le répertoire de l'opérateur).
    pub store: String,
    /// Répertoire des clés de signature.
    pub keys: String,
    /// Poussée après collecte, si configurée à l'installation.
    pub push: Option<PushConfig>,
}

impl InstallOptions {
    /// Les arguments passés à l'agent à chaque déclenchement : un
    /// `run --once` complet — le planificateur du système fait le reste.
    pub fn agent_args(&self) -> Vec<String> {
        let mut args = vec![
            "run".to_string(),
            "--once".to_string(),
            "--store".to_string(),
            self.store.clone(),
            "--keys".to_string(),
            self.keys.clone(),
        ];
        if let Some(push) = &self.push {
            args.push("--push".to_string());
            args.push("--server".to_string());
            args.push(push.server_url.clone());
            args.push("--cert".to_string());
            args.push(push.client_cert.display().to_string());
            args.push("--key".to_string());
            args.push(push.client_key.display().to_string());
            args.push("--ca".to_string());
            args.push(push.server_ca.display().to_string());
        }
        args
    }
}

/// Unité de service systemd : un `oneshot` qui exécute `run --once`.
///
/// Le durcissement est mécanique, pas déclaratif : chaque contrainte §7.1
/// est imposée par le noyau (capacités bornées, système de fichiers en
/// lecture seule hors magasin, filtre d'appels système), et chaque directive
/// est **commentée dans l'unité générée** — l'administrateur doit comprendre
/// ce qu'il déploie.
///
/// Le service démarre root (la collecte lit `/etc/shadow`, `sudoers`…), mais
/// en mode `--once` le binaire abandonne lui-même ses privilèges après la
/// collecte et avant toute connexion réseau ([`crate::privileges`]) : c'est
/// pourquoi `CAP_SETGID`/`CAP_SETUID` restent dans le périmètre des
/// capacités — sans eux, `setresuid` échouerait et la poussée serait
/// refusée. Le mode continu `run --every`, lui, ne peut pas abandonner
/// in-process (la collecte suivante relirait les fichiers protégés) : sa
/// réduction vient uniquement de ce durcissement — raison de plus pour
/// préférer le timer + `--once` installés ici.
pub fn systemd_service(options: &InstallOptions) -> String {
    let exec = std::iter::once(options.exe.clone())
        .chain(options.agent_args())
        .map(|a| unit_quote(&a))
        .collect::<Vec<_>>()
        .join(" ");

    let mut unit = format!(
        "# Généré par `constat-agent install`.\n\
         # Collecte Constat : lecture seule, aucun port en écoute, aucun code envoyé (§7.1).\n\
         #\n\
         # Le service démarre root : lire /etc/shadow ou sudoers l'exige. Ce que\n\
         # « root » peut faire ici est borné par les directives commentées plus bas,\n\
         # et le binaire abandonne lui-même ses privilèges (setgroups, setresgid,\n\
         # setresuid vers `constat` ou `nobody`) après la collecte et AVANT toute\n\
         # connexion réseau — c'est le mode --once planifié par le timer, recommandé\n\
         # précisément pour cela. Le mode continu `run --every` ne peut pas\n\
         # abandonner in-process (la collecte suivante relirait les fichiers\n\
         # protégés) : il ne serait couvert que par le présent durcissement.\n\
         [Unit]\n\
         Description=Constat — collecte d'état (lecture seule)\n\
         Documentation=https://github.com/yannbanas/constat\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         ExecStart={exec}\n\
         # Aucun gain de privilèges possible après le démarrage (bits setuid,\n\
         # capacités de fichiers… sont sans effet pour ce processus).\n\
         NoNewPrivileges=yes\n\
         # Capacités strictement nécessaires, tout le reste est hors d'atteinte\n\
         # (pas de mount, ptrace, module, raw-io…) :\n\
         #  - CAP_DAC_READ_SEARCH : lire les fichiers protégés (la collecte) ;\n\
         #  - CAP_SETGID, CAP_SETUID : permettre l'abandon de privilèges in-process\n\
         #    (setgroups/setresgid/setresuid) avant la poussée réseau — les retirer\n\
         #    ferait échouer l'abandon, donc refuser la poussée.\n\
         CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SETGID CAP_SETUID\n\
         # Aucune capacité ambiante : rien n'est transmis d'office au processus.\n\
         AmbientCapabilities=\n\
         # Les bits setuid/setgid des fichiers sont ignorés et impossibles à poser.\n\
         RestrictSUIDSGID=yes\n\
         # Tout fichier créé (magasin, verrous) n'est lisible que par son\n\
         # propriétaire.\n\
         UMask=0077\n"
    );
    if let Some(store_dir) = parent_unix(&options.store) {
        unit.push_str(
            "# Système de fichiers en lecture seule pour le service — imposé par le\n\
             # noyau, pas promis par le code : seul le répertoire du magasin s'écrit.\n",
        );
        unit.push_str("ProtectSystem=strict\n");
        unit.push_str("# L'unique exception : le répertoire du magasin (et des clés).\n");
        unit.push_str(&format!("ReadWritePaths={}\n", unit_quote(store_dir)));
    }
    unit.push_str(
        "# Les répertoires personnels restent lisibles (collecte) mais inaltérables.\n\
         ProtectHome=read-only\n\
         # /tmp privé au service : rien de partagé avec les autres processus.\n\
         PrivateTmp=yes\n\
         # /proc/sys, /sys… en lecture seule : la collecte lit, n'écrit jamais.\n\
         ProtectKernelTunables=yes\n\
         # Hiérarchie des cgroups en lecture seule.\n\
         ProtectControlGroups=yes\n\
         # Familles de sockets autorisées : TCP v4/v6 (poussée mTLS sortante) et\n\
         # Unix (journalisation systemd). Aucun socket brut, aucun netlink.\n\
         RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n\
         # Appels système restreints au profil @system-service de systemd (qui\n\
         # contient @setuid, nécessaire à l'abandon de privilèges) ; un appel hors\n\
         # profil termine le processus.\n\
         SystemCallFilter=@system-service\n\
         # Personnalité d'exécution verrouillée (pas de changement d'ABI).\n\
         LockPersonality=yes\n\
         # Aucune page mémoire à la fois inscriptible et exécutable : l'agent est\n\
         # du code compilé, il n'exécute jamais de code généré à l'exécution.\n\
         MemoryDenyWriteExecute=yes\n",
    );
    unit
}

/// Unité de timer systemd : déclenche le service à intervalle régulier,
/// avec un retard aléatoire (`RandomizedDelaySec`) qui joue le rôle de la
/// gigue du mode `--every`.
pub fn systemd_timer(options: &InstallOptions) -> String {
    let secs = every_secs(options.every);
    let delay = std::cmp::max(1, secs / 10);
    format!(
        "# Généré par `constat-agent install`.\n\
         [Unit]\n\
         Description=Constat — collecte planifiée (intervalle {secs} s)\n\
         \n\
         [Timer]\n\
         # Première collecte peu après l'amorçage, puis à intervalle régulier.\n\
         OnBootSec=2min\n\
         OnUnitActiveSec={secs}\n\
         # Gigue : jusqu'à 10 % de retard aléatoire, pour étaler le parc.\n\
         RandomizedDelaySec={delay}\n\
         # Rattrape une échéance manquée (machine éteinte) au démarrage suivant.\n\
         # Le trou de collecte reste déclaré dans la couverture (§4.2) — le\n\
         # rattrapage le referme plus vite, il ne le masque pas.\n\
         Persistent=true\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n"
    )
}

/// XML d'une tâche planifiée Windows, à enregistrer par l'opérateur avec
/// `schtasks /create /tn "Constat Agent" /xml <fichier>`.
///
/// La tâche tourne sous `S-1-5-18` (SYSTEM), et c'est dit honnêtement dans
/// le fichier généré : les lectures qu'exige la collecte (SAM, stratégie de
/// sécurité locale, GPO appliquées, ruches protégées du registre) sont
/// refusées à un compte à faible privilège, et Windows n'offre pas
/// d'équivalent de `CAP_DAC_READ_SEARCH` qui donnerait la lecture seule
/// sans le reste — l'abandon in-process du monde Unix
/// ([`crate::privileges`]) n'a pas de traduction ici. Ce qui borne SYSTEM
/// est la nature de l'agent (aucun port en écoute, aucune exécution de code
/// envoyé, lecture seule) plus les réglages de la tâche (une heure
/// d'exécution au plus, jamais deux instances).
///
/// `StartBoundary` est une date passée fixe —
/// avec une répétition indéfinie, seul l'intervalle compte, et la valeur
/// constante rend le fichier reproductible (même entrée, mêmes octets).
pub fn windows_task_xml(options: &InstallOptions) -> String {
    let interval = iso8601_duration(options.every);
    let delay = iso8601_duration(DurationMs(std::cmp::max(1_000, options.every.0 / 10)));
    let command = xml_escape(&options.exe);
    let arguments = xml_escape(
        &options
            .agent_args()
            .iter()
            .map(|a| win_arg_quote(a))
            .collect::<Vec<_>>()
            .join(" "),
    );
    format!(
        r#"<?xml version="1.0"?>
<!-- Généré par `constat-agent install` : collecte Constat, lecture seule (§7.1).

     Pourquoi SYSTEM (S-1-5-18), dit honnêtement : les lectures qu'exige la
     collecte (SAM, stratégie de sécurité locale, GPO appliquées, ruches
     protégées du registre) sont refusées à un compte à faible privilège, et
     Windows n'offre pas d'équivalent de CAP_DAC_READ_SEARCH qui donnerait la
     lecture seule sans le reste. SYSTEM reste borné par la nature de l'agent
     et par les réglages ci-dessous :
       * aucun port en écoute : poussée sortante mTLS uniquement ;
       * aucune exécution de code envoyé : collecteurs compilés dans le binaire,
         la réponse du serveur n'est jamais interprétée ;
       * lecture seule hors magasin et clés, secrets expurgés avant émission ;
       * une exécution limitée à une heure (ExecutionTimeLimit), jamais deux
         instances simultanées (MultipleInstancesPolicy). -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Constat — collecte d'état (lecture seule, aucun port en écoute)</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>{interval}</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2000-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <RandomDelay>{delay}</RandomDelay>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

/// Intervalle en secondes entières pour systemd, arrondi au supérieur,
/// jamais nul (la granularité d'un timer systemd est la seconde).
fn every_secs(every: DurationMs) -> u64 {
    std::cmp::max(1, every.0.div_ceil(1_000))
}

/// Durée ISO 8601 pour le Planificateur de tâches : `PT6H`, `PT30M`,
/// `P1DT2H`… Arrondie à la seconde supérieure, jamais nulle (le
/// Planificateur ne descend pas sous la seconde).
pub fn iso8601_duration(d: DurationMs) -> String {
    let total = std::cmp::max(1, d.0.div_ceil(1_000));
    let days = total / 86_400;
    let hours = (total % 86_400) / 3_600;
    let minutes = (total % 3_600) / 60;
    let seconds = total % 60;
    let mut out = String::from("P");
    if days > 0 {
        out.push_str(&format!("{days}D"));
    }
    if hours > 0 || minutes > 0 || seconds > 0 {
        out.push('T');
        if hours > 0 {
            out.push_str(&format!("{hours}H"));
        }
        if minutes > 0 {
            out.push_str(&format!("{minutes}M"));
        }
        if seconds > 0 {
            out.push_str(&format!("{seconds}S"));
        }
    }
    out
}

/// Répertoire parent d'un chemin cible Linux (séparateur `/` uniquement :
/// le chemin décrit la machine cible, pas celle qui génère). `None` si le
/// chemin n'a pas de parent exploitable — le durcissement est alors omis.
/// Public : le binaire s'en sert pour afficher le `mkdir -p` à lancer.
pub fn parent_unix(path: &str) -> Option<&str> {
    match path.rsplit_once('/') {
        Some(("", _)) => Some("/"),
        Some((dir, _)) if !dir.is_empty() => Some(dir),
        _ => None,
    }
}

/// Cite un argument pour une ligne `ExecStart=` systemd : guillemets
/// doubles si l'argument contient un espace ou un caractère à protéger.
fn unit_quote(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\\' || c == '\'')
    {
        return arg.to_string();
    }
    let escaped = arg.replace('\\', r"\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Cite un argument pour la ligne de commande Windows (avant échappement
/// XML) : guillemets doubles autour des arguments contenant un espace.
fn win_arg_quote(arg: &str) -> String {
    if arg.is_empty() || arg.chars().any(char::is_whitespace) {
        format!("\"{arg}\"")
    } else {
        arg.to_string()
    }
}

/// Échappement XML minimal pour du texte d'élément.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn options() -> InstallOptions {
        InstallOptions {
            every: DurationMs(6 * 3_600_000),
            exe: "/usr/local/bin/constat-agent".to_string(),
            store: "/var/lib/constat/constat.redb".to_string(),
            keys: "/var/lib/constat/agent.keys".to_string(),
            push: None,
        }
    }

    fn options_avec_poussee() -> InstallOptions {
        InstallOptions {
            push: Some(PushConfig {
                server_url: "https://constat.interne:8443".to_string(),
                client_cert: PathBuf::from("/etc/constat/agent.pem"),
                client_key: PathBuf::from("/etc/constat/agent.key.pem"),
                server_ca: PathBuf::from("/etc/constat/ca.pem"),
            }),
            ..options()
        }
    }

    #[test]
    fn service_systemd_oneshot_run_once() {
        let unit = systemd_service(&options());
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("Type=oneshot"));
        assert!(unit.contains(
            "ExecStart=/usr/local/bin/constat-agent run --once \
             --store /var/lib/constat/constat.redb --keys /var/lib/constat/agent.keys"
        ));
        // Durcissement mécanique : lecture seule hors répertoire du magasin.
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("ReadWritePaths=/var/lib/constat"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        // Sans poussée configurée, aucune option de poussée.
        assert!(!unit.contains("--push"));
    }

    /// Le durcissement complet (§7.1) : chaque directive attendue est là,
    /// exactement.
    #[test]
    fn service_systemd_durci() {
        let unit = systemd_service(&options());
        for directive in [
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SETGID CAP_SETUID",
            "AmbientCapabilities=",
            "RestrictSUIDSGID=yes",
            "UMask=0077",
            "ProtectSystem=strict",
            "ReadWritePaths=/var/lib/constat",
            "ProtectHome=read-only",
            "PrivateTmp=yes",
            "ProtectKernelTunables=yes",
            "ProtectControlGroups=yes",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
            "SystemCallFilter=@system-service",
            "LockPersonality=yes",
            "MemoryDenyWriteExecute=yes",
        ] {
            assert!(
                unit.lines().any(|l| l == directive),
                "directive manquante ou altérée : {directive}\n{unit}"
            );
        }
        // AmbientCapabilities est bien VIDE (pas de capacité ambiante).
        assert!(!unit.contains("AmbientCapabilities=CAP"));
    }

    /// Chaque directive de durcissement est précédée d'un commentaire :
    /// l'administrateur doit comprendre ce qu'il déploie.
    #[test]
    fn service_systemd_directives_commentees() {
        let unit = systemd_service(&options());
        let lines: Vec<&str> = unit.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let est_directive = line.contains('=')
                && !line.starts_with('#')
                && !line.starts_with("Type=")
                && !line.starts_with("ExecStart=")
                && !line.starts_with("Description=")
                && !line.starts_with("Documentation=");
            if est_directive {
                assert!(
                    i > 0 && lines[i - 1].starts_with('#'),
                    "directive sans commentaire au-dessus : {line}"
                );
            }
        }
    }

    /// L'abandon in-process exige CAP_SETUID/CAP_SETGID : l'unité les
    /// documente comme tels (les retirer casserait l'abandon, donc la
    /// poussée).
    #[test]
    fn service_systemd_documente_l_abandon() {
        let unit = systemd_service(&options());
        assert!(unit.contains("abandonne lui-même ses privilèges"));
        assert!(unit.contains("AVANT toute"));
        assert!(unit.contains("`run --every` ne peut pas"));
    }

    #[test]
    fn service_systemd_avec_poussee() {
        let unit = systemd_service(&options_avec_poussee());
        assert!(unit.contains("--push --server https://constat.interne:8443"));
        assert!(unit.contains("--cert /etc/constat/agent.pem"));
        assert!(unit.contains("--key /etc/constat/agent.key.pem"));
        assert!(unit.contains("--ca /etc/constat/ca.pem"));
    }

    #[test]
    fn timer_systemd_intervalle_et_gigue() {
        let timer = systemd_timer(&options());
        assert!(timer.contains("OnUnitActiveSec=21600")); // 6 h
        assert!(timer.contains("RandomizedDelaySec=2160")); // 10 %
        assert!(timer.contains("Persistent=true"));
        assert!(timer.contains("WantedBy=timers.target"));
        assert!(timer.contains("OnBootSec=2min"));
    }

    #[test]
    fn tache_windows_intervalle_gigue_et_action() {
        let opts = InstallOptions {
            exe: r"C:\Program Files\Constat\constat-agent.exe".to_string(),
            store: r"C:\ProgramData\Constat\constat.redb".to_string(),
            keys: r"C:\ProgramData\Constat\agent.keys".to_string(),
            ..options()
        };
        let xml = windows_task_xml(&opts);
        assert!(xml.contains("<Interval>PT6H</Interval>"));
        assert!(xml.contains("<RandomDelay>PT36M</RandomDelay>")); // 10 % de 6 h
                                                                   // Le chemin avec espace est cité ; l'action est bien `run --once`.
        assert!(xml.contains(r"<Command>C:\Program Files\Constat\constat-agent.exe</Command>"));
        assert!(xml.contains(r"<Arguments>run --once --store C:\ProgramData\Constat\constat.redb"));
        // SYSTEM : les collecteurs lisent des configurations protégées.
        assert!(xml.contains("<UserId>S-1-5-18</UserId>"));
        assert!(xml.contains("<StopAtDurationEnd>false</StopAtDurationEnd>"));
    }

    /// La tâche Windows documente honnêtement pourquoi SYSTEM est requis et
    /// ce qui le borne — dans le fichier même que l'opérateur enregistre.
    #[test]
    fn tache_windows_documente_system() {
        let xml = windows_task_xml(&options());
        assert!(xml.contains("Pourquoi SYSTEM"));
        assert!(xml.contains("CAP_DAC_READ_SEARCH"));
        assert!(xml.contains("aucun port en écoute"));
        assert!(xml.contains("aucune exécution de code envoyé"));
        // Bornes mécaniques citées ET présentes dans les réglages.
        assert!(xml.contains("<ExecutionTimeLimit>PT1H</ExecutionTimeLimit>"));
        assert!(xml.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
        // Un commentaire XML ne doit jamais contenir « -- » : le fichier
        // deviendrait invalide pour schtasks.
        let comment = xml
            .split("<!--")
            .nth(1)
            .and_then(|s| s.split("-->").next())
            .unwrap();
        assert!(
            !comment.contains("--"),
            "« -- » interdit en commentaire XML"
        );
    }

    #[test]
    fn tache_windows_echappe_le_xml() {
        let opts = InstallOptions {
            store: r"C:\Data & Co\constat.redb".to_string(),
            ..options()
        };
        let xml = windows_task_xml(&opts);
        assert!(xml.contains("&amp; Co"));
        assert!(!xml.contains("Data & Co")); // le `&` nu casserait le XML
                                             // L'argument avec espace est entre guillemets.
        assert!(xml.contains(r#""C:\Data &amp; Co\constat.redb""#));
    }

    #[test]
    fn durees_iso8601() {
        assert_eq!(iso8601_duration(DurationMs(6 * 3_600_000)), "PT6H");
        assert_eq!(iso8601_duration(DurationMs(30 * 60_000)), "PT30M");
        assert_eq!(iso8601_duration(DurationMs(90_000)), "PT1M30S");
        assert_eq!(iso8601_duration(DurationMs(26 * 3_600_000)), "P1DT2H");
        assert_eq!(iso8601_duration(DurationMs(86_400_000)), "P1D");
        // Sous la seconde : arrondi à la seconde, jamais nul.
        assert_eq!(iso8601_duration(DurationMs(200)), "PT1S");
    }

    #[test]
    fn parent_unix_extrait_le_repertoire() {
        assert_eq!(
            parent_unix("/var/lib/constat/constat.redb"),
            Some("/var/lib/constat")
        );
        assert_eq!(parent_unix("/constat.redb"), Some("/"));
        assert_eq!(parent_unix("constat.redb"), None);
    }

    #[test]
    fn citation_systemd() {
        assert_eq!(unit_quote("simple"), "simple");
        assert_eq!(unit_quote("/avec espace/x"), "\"/avec espace/x\"");
        assert_eq!(unit_quote(""), "\"\"");
    }
}
