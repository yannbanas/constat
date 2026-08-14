//! Abandon de privilèges après collecte (§7.1) — l'agent tient lui-même sa
//! promesse de « privilèges minimaux » au lieu de la déléguer entièrement au
//! durcissement systemd.
//!
//! # Modèle de menace : pourquoi abandonner AVANT le réseau
//!
//! L'agent démarre root quand la collecte l'exige : lire `/etc/shadow` ou
//! `sudoers` ne se fait pas autrement. Mais la phase risquée n'est pas la
//! lecture de fichiers locaux — c'est la **phase réseau**, seul moment où le
//! processus est exposé à des octets choisis par un pair distant (la poignée
//! de main TLS et la ligne de statut HTTP ; le corps de la réponse n'est
//! jamais interprété, voir [`crate::push`]). Si un défaut de l'analyse TLS
//! ou HTTP était un jour exploité, le processus compromis doit être
//! `nobody`, pas root : il ne peut alors ni relire `/etc/shadow`, ni écrire
//! le magasin, ni redevenir root — la « réduction du rayon d'explosion »
//! de §7.1.
//!
//! D'où l'ordre strict du mode `--once` : collecter → écrire et signer le
//! magasin → préparer **en mémoire** ce que la poussée relira → fermer le
//! magasin → **abandonner définitivement les privilèges** → pousser.
//! L'abandon est obligatoire : s'il échoue, la poussée est refusée plutôt
//! que faite en root (l'échappatoire explicite et déconseillée est
//! `--allow-root-push`).
//!
//! # Ce que l'abandon n'empêche pas
//!
//! - une compromission **pendant** la collecte : l'analyse des fichiers
//!   locaux s'exécute root — sa surface est du contenu local, pas distant ;
//! - un agent compromis qui mentirait sur l'état de sa machine (limite
//!   déclarée du produit) ;
//! - la lecture, par le processus abandonné, de ce qu'il détient déjà en
//!   mémoire : le lot à pousser (déjà expurgé, §7.2) et le matériel TLS,
//!   chargés avant l'abandon — c'est exactement ce qui doit partir sur le
//!   réseau, rien de plus ;
//! - rien côté Windows : la tâche planifiée tourne en SYSTEM (les lectures
//!   qu'exige la collecte y sont refusées aux comptes à faible privilège) ;
//!   ce qui borne SYSTEM est documenté dans le fichier généré par `install`.
//!
//! # La séquence, et pourquoi cet ordre
//!
//! 1. `setgroups([])` — purger les groupes supplémentaires **d'abord** :
//!    après la perte du gid puis de l'uid 0, l'appel serait refusé, et des
//!    groupes hérités (ex. `shadow`) survivraient à l'abandon ;
//! 2. `setresgid(gid, gid, gid)` — le gid **avant** l'uid : une fois
//!    l'uid 0 abandonné, changer de gid est refusé ;
//! 3. `setresuid(uid, uid, uid)` — réel, effectif **et sauvé** en dernier :
//!    la porte se referme ici (un uid sauvé resté 0 permettrait de revenir) ;
//! 4. vérification post-abandon : l'euid observé est la cible, et
//!    `setuid(0)` **doit échouer** — s'il réussit, l'abandon n'était pas
//!    réel et l'agent échoue bruyamment au lieu de pousser.
//!
//! # Mode continu (`--every`) : le compromis, dit honnêtement
//!
//! Abandonner après la première collecte rendrait toutes les suivantes
//! impossibles — relire `/etc/shadow` au cycle suivant exige les
//! privilèges. Le mode continu n'abandonne donc **pas** in-process : sa
//! réduction vient du durcissement de l'unité systemd générée par `install`
//! (capacités bornées, système de fichiers en lecture seule, filtre
//! d'appels système…). Le mode recommandé reste le timer système +
//! `run --once`, qui abandonne systématiquement avant chaque poussée.
//!
//! # Utilisateur cible et permissions
//!
//! `--run-as <utilisateur>` ; à défaut, `constat` s'il existe, sinon
//! `nobody` ([`DEFAULT_TARGET_USERS`]), résolus par `getpwnam_r` avant
//! l'abandon. Aucun fichier n'est relu après l'abandon : le lot est
//! construit magasin encore ouvert (le magasin redb ne s'ouvre qu'en
//! lecture-écriture — rendre le magasin inscriptible par `nobody` serait
//! pire que garder en mémoire un lot déjà expurgé), et le matériel TLS est
//! chargé avant (la clé cliente peut donc rester lisible par root seul,
//! 0600).
//!
//! Les appels système sont derrière le trait [`PrivilegeOps`] : la séquence
//! et tous ses chemins d'échec se testent sans être root, sur toutes les
//! plateformes ; seule l'implémentation réelle ([`drop_now`]) touche libc,
//! sous `cfg(unix)`.

/// Candidats par défaut de l'abandon, dans l'ordre de préférence : le
/// compte de service dédié s'il existe, sinon le compte sans privilèges
/// universel.
pub const DEFAULT_TARGET_USERS: [&str; 2] = ["constat", "nobody"];

/// L'utilisateur vers lequel les privilèges sont abandonnés.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetUser {
    /// Nom du compte (tel que résolu).
    pub name: String,
    /// Uid numérique cible.
    pub uid: u32,
    /// Gid principal du compte.
    pub gid: u32,
}

/// Erreurs de résolution ou d'abandon. Chaque échec **refuse la poussée** :
/// l'agent ne pousse jamais en root par accident.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum PrivilegeError {
    /// L'utilisateur demandé via `--run-as` n'existe pas.
    #[error("utilisateur cible inconnu : « {name} »")]
    #[diagnostic(help(
        "créez le compte, ou passez --run-as <utilisateur> existant ; \
         sans --run-as, l'agent essaie « constat » puis « nobody »"
    ))]
    UnknownUser { name: String },

    /// Aucun candidat par défaut n'existe sur cette machine.
    #[error("aucun utilisateur cible : ni « constat » ni « nobody » n'existent")]
    #[diagnostic(help(
        "créez un compte de service (ex. `useradd --system --shell /usr/sbin/nologin constat`), \
         précisez --run-as, ou — déconseillé — poussez sans abandon avec --allow-root-push"
    ))]
    NoDefaultUser,

    /// La cible est uid 0 : « abandonner » vers root n'est pas un abandon.
    #[error("l'utilisateur cible « {name} » est uid 0 : ce ne serait pas un abandon")]
    #[diagnostic(help("choisissez un compte sans privilèges (constat, nobody…)"))]
    TargetIsRoot { name: String },

    /// L'agent ne démarre pas root : il n'y a rien à abandonner.
    #[error("euid {euid} : l'abandon de privilèges exige de démarrer root (euid 0)")]
    NotRoot { euid: u32 },

    /// Une étape de la séquence a échoué : la séquence s'arrête là.
    #[error("abandon de privilèges : l'étape {step} a échoué : {cause}")]
    #[diagnostic(help(
        "la poussée est refusée plutôt que faite en root ; vérifiez les capacités \
         du service (CAP_SETUID et CAP_SETGID doivent rester dans \
         CapabilityBoundingSet), ou — déconseillé — utilisez --allow-root-push"
    ))]
    Step { step: &'static str, cause: String },

    /// L'euid observé après la séquence n'est pas la cible.
    #[error("vérification post-abandon : euid attendu {expected}, observé {actual}")]
    Verify { expected: u32, actual: u32 },

    /// `setuid(0)` a réussi après l'abandon : la réacquisition est possible.
    #[error(
        "vérification post-abandon : setuid(0) a RÉUSSI — la réacquisition de root est encore possible"
    )]
    #[diagnostic(help(
        "l'abandon n'était pas réel (uid sauvé resté 0 ?) ; la poussée est refusée — \
         ce cas ne doit jamais se produire, signalez-le"
    ))]
    RegainPossible,

    /// Plateforme sans notion d'abandon in-process (Windows).
    #[error("abandon de privilèges sans objet sur cette plateforme")]
    #[diagnostic(help(
        "sous Windows la tâche planifiée tourne en SYSTEM ; ce qui la borne est \
         documenté dans le fichier généré par `constat-agent install`"
    ))]
    Unsupported,
}

/// Les appels système de l'abandon, derrière un trait : la **séquence** (et
/// chacun de ses chemins d'échec) se teste sans être root et sur toutes les
/// plateformes ; seul [`drop_now`] branche l'implémentation libc réelle.
pub trait PrivilegeOps {
    /// Uid effectif courant.
    fn euid(&self) -> u32;
    /// Résolution d'un compte : `Some((uid, gid))` s'il existe.
    fn lookup_user(&self, name: &str) -> Option<(u32, u32)>;
    /// `setgroups(0, [])` : purge des groupes supplémentaires.
    fn setgroups_empty(&mut self) -> Result<(), String>;
    /// `setresgid(gid, gid, gid)` : gid réel, effectif et sauvé.
    fn setresgid_all(&mut self, gid: u32) -> Result<(), String>;
    /// `setresuid(uid, uid, uid)` : uid réel, effectif et sauvé.
    fn setresuid_all(&mut self, uid: u32) -> Result<(), String>;
    /// Tentative de réacquisition : `setuid(0)`. Renvoie `true` si l'appel a
    /// **réussi** — c'est-à-dire si l'abandon a échoué.
    fn setuid_root_succeeds(&mut self) -> bool;
}

/// Résout l'utilisateur cible : `--run-as` s'il est fourni, sinon le premier
/// existant de [`DEFAULT_TARGET_USERS`] (« constat », puis « nobody »).
pub fn resolve_target(
    ops: &dyn PrivilegeOps,
    explicit: Option<&str>,
) -> Result<TargetUser, PrivilegeError> {
    match explicit {
        Some(name) => match ops.lookup_user(name) {
            Some((uid, gid)) => Ok(TargetUser {
                name: name.to_string(),
                uid,
                gid,
            }),
            None => Err(PrivilegeError::UnknownUser {
                name: name.to_string(),
            }),
        },
        None => {
            for name in DEFAULT_TARGET_USERS {
                if let Some((uid, gid)) = ops.lookup_user(name) {
                    return Ok(TargetUser {
                        name: name.to_string(),
                        uid,
                        gid,
                    });
                }
            }
            Err(PrivilegeError::NoDefaultUser)
        }
    }
}

/// L'abandon lui-même : `setgroups([])` → `setresgid` → `setresuid`, puis
/// vérification que la réacquisition est impossible.
///
/// L'ordre est **porteur de sens** (voir la documentation du module) : les
/// groupes d'abord, le gid ensuite, l'uid en dernier. Chaque étape en échec
/// interrompt la séquence et l'erreur est fatale pour l'appelant — jamais de
/// poussée « quand même ».
pub fn drop_privileges(
    ops: &mut dyn PrivilegeOps,
    target: &TargetUser,
) -> Result<(), PrivilegeError> {
    // Garde-fou : « abandonner » vers uid 0 serait un mensonge.
    if target.uid == 0 {
        return Err(PrivilegeError::TargetIsRoot {
            name: target.name.clone(),
        });
    }
    let euid = ops.euid();
    if euid != 0 {
        return Err(PrivilegeError::NotRoot { euid });
    }

    // 1. Groupes supplémentaires d'abord : après la perte du gid/uid 0,
    //    l'appel serait refusé et des groupes hérités (ex. `shadow`)
    //    survivraient à l'abandon.
    ops.setgroups_empty()
        .map_err(|cause| PrivilegeError::Step {
            step: "setgroups",
            cause,
        })?;
    // 2. Le gid avant l'uid : une fois l'uid 0 abandonné, changer de gid
    //    est refusé.
    ops.setresgid_all(target.gid)
        .map_err(|cause| PrivilegeError::Step {
            step: "setresgid",
            cause,
        })?;
    // 3. L'uid en dernier — réel, effectif ET sauvé : la porte se referme
    //    ici. Un uid sauvé resté 0 permettrait de revenir ; setresuid les
    //    change tous les trois.
    ops.setresuid_all(target.uid)
        .map_err(|cause| PrivilegeError::Step {
            step: "setresuid",
            cause,
        })?;

    // Vérification post-abandon, dans le code et pas seulement sur le
    // papier : l'euid est la cible, et la réacquisition est impossible.
    let actual = ops.euid();
    if actual != target.uid {
        return Err(PrivilegeError::Verify {
            expected: target.uid,
            actual,
        });
    }
    if ops.setuid_root_succeeds() {
        // Échec bruyant : si setuid(0) réussit, l'abandon n'était pas réel.
        return Err(PrivilegeError::RegainPossible);
    }
    Ok(())
}

/// Vrai si le processus courant est root (euid 0). Toujours faux hors Unix.
#[cfg(unix)]
pub fn running_as_root() -> bool {
    imp::LibcOps.euid() == 0
}

/// Vrai si le processus courant est root (euid 0). Toujours faux hors Unix.
#[cfg(not(unix))]
pub fn running_as_root() -> bool {
    false
}

/// Résout la cible puis abandonne les privilèges du processus courant,
/// définitivement. À n'appeler qu'une fois le magasin fermé et le matériel
/// de poussée chargé en mémoire — plus aucun fichier protégé n'est lisible
/// ensuite.
#[cfg(unix)]
pub fn drop_now(run_as: Option<&str>) -> Result<TargetUser, PrivilegeError> {
    let mut ops = imp::LibcOps;
    let target = resolve_target(&ops, run_as)?;
    drop_privileges(&mut ops, &target)?;
    Ok(target)
}

/// Hors Unix, l'abandon in-process n'existe pas : l'appel est refusé (les
/// chemins appelants ne l'atteignent jamais, `running_as_root` y est faux).
#[cfg(not(unix))]
pub fn drop_now(_run_as: Option<&str>) -> Result<TargetUser, PrivilegeError> {
    Err(PrivilegeError::Unsupported)
}

/// L'implémentation réelle : libc, uniquement ici.
#[cfg(unix)]
mod imp {
    // SÉCURITÉ (§17) : l'unique `unsafe` du crate. Le workspace interdit
    // l'unsafe ; ce module porte l'exception justifiée — setgroups,
    // setresgid, setresuid, setuid, geteuid et getpwnam_r n'ont aucune
    // interface sûre dans la bibliothèque standard, et une dépendance
    // d'enrobage (nix…) ajouterait du code non audité pour six appels
    // triviaux. Chaque bloc `unsafe` tient en une ligne et ne manipule
    // aucune mémoire partagée.
    #![allow(unsafe_code)]

    use super::PrivilegeOps;

    /// Les vrais appels système.
    pub struct LibcOps;

    impl PrivilegeOps for LibcOps {
        fn euid(&self) -> u32 {
            // geteuid ne peut pas échouer (POSIX).
            unsafe { libc::geteuid() }
        }

        fn lookup_user(&self, name: &str) -> Option<(u32, u32)> {
            let cname = std::ffi::CString::new(name).ok()?;
            let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
            // 16 Kio couvrent largement _SC_GETPW_R_SIZE_MAX sur les
            // systèmes courants (souvent 1024) ; un compte introuvable ou
            // une erreur rendent tous deux None — l'appelant dit lequel
            // des candidats manquait.
            let mut buf = vec![0u8; 16 * 1024];
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let rc = unsafe {
                libc::getpwnam_r(
                    cname.as_ptr(),
                    pwd.as_mut_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    &mut result,
                )
            };
            if rc == 0 && !result.is_null() {
                // getpwnam_r a rempli la structure : la lire est sûr.
                let pwd = unsafe { pwd.assume_init() };
                Some((pwd.pw_uid, pwd.pw_gid))
            } else {
                None
            }
        }

        fn setgroups_empty(&mut self) -> Result<(), String> {
            let rc = unsafe { libc::setgroups(0, std::ptr::null()) };
            if rc == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error().to_string())
            }
        }

        fn setresgid_all(&mut self, gid: u32) -> Result<(), String> {
            let rc = unsafe { libc::setresgid(gid, gid, gid) };
            if rc == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error().to_string())
            }
        }

        fn setresuid_all(&mut self, uid: u32) -> Result<(), String> {
            let rc = unsafe { libc::setresuid(uid, uid, uid) };
            if rc == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error().to_string())
            }
        }

        fn setuid_root_succeeds(&mut self) -> bool {
            // La tentative de réacquisition DOIT échouer ; si elle réussit,
            // l'appelant échoue bruyamment (RegainPossible).
            unsafe { libc::setuid(0) == 0 }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// Implémentation simulée : enregistre la séquence d'appels, peut faire
    /// échouer une étape donnée, et simule (ou non) la prise d'effet du
    /// changement d'uid.
    struct Mock {
        euid: Cell<u32>,
        users: Vec<(String, u32, u32)>,
        fail_step: Option<&'static str>,
        regain_succeeds: bool,
        /// Si vrai, setresuid « réussit » sans changer l'euid observé —
        /// pour tester la vérification post-abandon.
        stick_euid: bool,
        calls: RefCell<Vec<String>>,
    }

    impl Mock {
        fn root() -> Self {
            Mock {
                euid: Cell::new(0),
                users: vec![
                    ("constat".into(), 990, 990),
                    ("nobody".into(), 65534, 65534),
                ],
                fail_step: None,
                regain_succeeds: false,
                stick_euid: false,
                calls: RefCell::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        fn record(&self, call: impl Into<String>) {
            self.calls.borrow_mut().push(call.into());
        }
    }

    impl PrivilegeOps for Mock {
        fn euid(&self) -> u32 {
            self.record("geteuid");
            self.euid.get()
        }
        fn lookup_user(&self, name: &str) -> Option<(u32, u32)> {
            self.users
                .iter()
                .find(|(n, _, _)| n == name)
                .map(|&(_, uid, gid)| (uid, gid))
        }
        fn setgroups_empty(&mut self) -> Result<(), String> {
            self.record("setgroups");
            if self.fail_step == Some("setgroups") {
                return Err("EPERM (simulé)".into());
            }
            Ok(())
        }
        fn setresgid_all(&mut self, gid: u32) -> Result<(), String> {
            self.record(format!("setresgid({gid})"));
            if self.fail_step == Some("setresgid") {
                return Err("EPERM (simulé)".into());
            }
            Ok(())
        }
        fn setresuid_all(&mut self, uid: u32) -> Result<(), String> {
            self.record(format!("setresuid({uid})"));
            if self.fail_step == Some("setresuid") {
                return Err("EPERM (simulé)".into());
            }
            if !self.stick_euid {
                self.euid.set(uid);
            }
            Ok(())
        }
        fn setuid_root_succeeds(&mut self) -> bool {
            self.record("setuid(0)");
            self.regain_succeeds
        }
    }

    fn nobody() -> TargetUser {
        TargetUser {
            name: "nobody".into(),
            uid: 65534,
            gid: 65534,
        }
    }

    fn pos(calls: &[String], name: &str) -> usize {
        calls
            .iter()
            .position(|c| c == name)
            .unwrap_or_else(|| panic!("appel absent : {name} dans {calls:?}"))
    }

    /// La séquence complète, dans l'ordre porteur de sens : groupes, puis
    /// gid, puis uid, puis tentative de réacquisition (qui doit échouer).
    #[test]
    fn sequence_complete_et_ordonnee() {
        let mut mock = Mock::root();
        drop_privileges(&mut mock, &nobody()).unwrap();
        let calls = mock.calls();
        let groups = pos(&calls, "setgroups");
        let gid = pos(&calls, "setresgid(65534)");
        let uid = pos(&calls, "setresuid(65534)");
        let regain = pos(&calls, "setuid(0)");
        assert!(
            groups < gid && gid < uid && uid < regain,
            "ordre invalide : {calls:?}"
        );
    }

    /// Sans euid 0, rien à abandonner : erreur, et aucun appel de mutation.
    #[test]
    fn refus_sans_root() {
        let mut mock = Mock::root();
        mock.euid.set(1000);
        let err = drop_privileges(&mut mock, &nobody()).unwrap_err();
        assert!(matches!(err, PrivilegeError::NotRoot { euid: 1000 }));
        assert!(
            !mock.calls().iter().any(|c| c.starts_with("set")),
            "aucune mutation ne doit être tentée : {:?}",
            mock.calls()
        );
    }

    /// Une cible uid 0 est refusée avant tout appel : ce ne serait pas un
    /// abandon.
    #[test]
    fn refus_cible_root() {
        let mut mock = Mock::root();
        let target = TargetUser {
            name: "root".into(),
            uid: 0,
            gid: 0,
        };
        let err = drop_privileges(&mut mock, &target).unwrap_err();
        assert!(matches!(err, PrivilegeError::TargetIsRoot { .. }));
        assert!(mock.calls().is_empty());
    }

    /// setgroups en échec : la séquence s'arrête là, ni gid ni uid tentés.
    #[test]
    fn echec_setgroups_interrompt() {
        let mut mock = Mock::root();
        mock.fail_step = Some("setgroups");
        let err = drop_privileges(&mut mock, &nobody()).unwrap_err();
        assert!(matches!(
            err,
            PrivilegeError::Step {
                step: "setgroups",
                ..
            }
        ));
        let calls = mock.calls();
        assert!(!calls.iter().any(|c| c.starts_with("setresgid")));
        assert!(!calls.iter().any(|c| c.starts_with("setresuid")));
    }

    /// setresgid en échec : l'uid n'est jamais touché.
    #[test]
    fn echec_setresgid_interrompt() {
        let mut mock = Mock::root();
        mock.fail_step = Some("setresgid");
        let err = drop_privileges(&mut mock, &nobody()).unwrap_err();
        assert!(matches!(
            err,
            PrivilegeError::Step {
                step: "setresgid",
                ..
            }
        ));
        assert!(!mock.calls().iter().any(|c| c.starts_with("setresuid")));
    }

    /// setresuid en échec : erreur nommant l'étape.
    #[test]
    fn echec_setresuid_declare() {
        let mut mock = Mock::root();
        mock.fail_step = Some("setresuid");
        let err = drop_privileges(&mut mock, &nobody()).unwrap_err();
        assert!(matches!(
            err,
            PrivilegeError::Step {
                step: "setresuid",
                ..
            }
        ));
    }

    /// setresuid « réussit » mais l'euid observé n'a pas changé : la
    /// vérification post-abandon échoue, sans même tenter setuid(0).
    #[test]
    fn verification_euid_apres_abandon() {
        let mut mock = Mock::root();
        mock.stick_euid = true;
        let err = drop_privileges(&mut mock, &nobody()).unwrap_err();
        assert!(matches!(
            err,
            PrivilegeError::Verify {
                expected: 65534,
                actual: 0
            }
        ));
        assert!(!mock.calls().iter().any(|c| c == "setuid(0)"));
    }

    /// setuid(0) réussit après l'abandon : échec bruyant, jamais silencieux.
    #[test]
    fn reacquisition_possible_est_fatale() {
        let mut mock = Mock::root();
        mock.regain_succeeds = true;
        let err = drop_privileges(&mut mock, &nobody()).unwrap_err();
        assert!(matches!(err, PrivilegeError::RegainPossible));
    }

    /// --run-as explicite : le compte est résolu tel quel.
    #[test]
    fn resolution_explicite() {
        let mock = Mock::root();
        let target = resolve_target(&mock, Some("constat")).unwrap();
        assert_eq!(
            target,
            TargetUser {
                name: "constat".into(),
                uid: 990,
                gid: 990
            }
        );
    }

    /// --run-as inconnu : erreur nommant le compte.
    #[test]
    fn resolution_explicite_inconnue() {
        let mock = Mock::root();
        let err = resolve_target(&mock, Some("fantome")).unwrap_err();
        assert!(matches!(err, PrivilegeError::UnknownUser { name } if name == "fantome"));
    }

    /// Sans --run-as : `constat` est préféré à `nobody` quand il existe.
    #[test]
    fn resolution_defaut_prefere_constat() {
        let mock = Mock::root();
        assert_eq!(resolve_target(&mock, None).unwrap().name, "constat");
    }

    /// Sans compte `constat`, repli sur `nobody`.
    #[test]
    fn resolution_defaut_replie_sur_nobody() {
        let mut mock = Mock::root();
        mock.users.retain(|(n, _, _)| n != "constat");
        assert_eq!(resolve_target(&mock, None).unwrap().name, "nobody");
    }

    /// Ni `constat` ni `nobody` : erreur explicite (jamais de poussée root
    /// par accident).
    #[test]
    fn resolution_sans_candidat() {
        let mut mock = Mock::root();
        mock.users.clear();
        assert!(matches!(
            resolve_target(&mock, None).unwrap_err(),
            PrivilegeError::NoDefaultUser
        ));
    }

    /// Unix, implémentation réelle : `root` se résout (uid 0), un compte
    /// fantaisiste non ; et sans euid 0, `drop_now` refuse.
    #[cfg(unix)]
    #[test]
    fn libc_resolution_reelle() {
        let ops = super::imp::LibcOps;
        assert_eq!(ops.lookup_user("root").map(|(uid, _)| uid), Some(0));
        assert_eq!(ops.lookup_user("constat-compte-inexistant"), None);
        if !running_as_root() {
            assert!(drop_now(None).is_err());
        }
    }

    /// Hors Unix : pas d'abandon in-process, et l'appel direct est refusé.
    #[cfg(not(unix))]
    #[test]
    fn plateforme_sans_abandon() {
        assert!(!running_as_root());
        assert!(matches!(drop_now(None), Err(PrivilegeError::Unsupported)));
    }
}
