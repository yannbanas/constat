//! Planification interne : le mode continu `constat-agent run --every <durée>`.
//!
//! Une boucle simple dans le processus : collecter, dormir, recommencer.
//! Aucun port en écoute, aucun fil d'attente, aucun démon caché — juste un
//! `thread::sleep` entre deux cycles (§7.1).
//!
//! # Gigue aléatoire ±10 %
//!
//! Sur un parc installé depuis la même image et démarré par le même
//! orchestrateur, tous les agents collecteraient — et pousseraient — à la
//! même seconde. Chaque intervalle est donc tiré uniformément dans
//! [90 %, 110 %] de l'intervalle demandé ([`jittered_ms`]) : les collectes
//! se désynchronisent d'elles-mêmes au fil des cycles.
//!
//! La source d'aléa est un petit générateur congruentiel linéaire ([`Lcg`])
//! semé sur l'horloge et l'identifiant de processus. Ce n'est **pas** de la
//! cryptographie et rien ici n'en demande : il s'agit seulement d'étaler un
//! parc dans le temps. Aucune dépendance ajoutée (§17).
//!
//! # Arrêt : Ctrl-C n'est pas intercepté — choix documenté
//!
//! L'agent laisse le comportement par défaut du système (Ctrl-C, SIGTERM,
//! fermeture de console) terminer le processus, y compris au milieu d'un
//! cycle. C'est brutal mais **sans danger** :
//!
//! - le magasin est transactionnel (redb) : une collecte est journalisée
//!   entièrement ou pas du tout, jamais à moitié ;
//! - la poussée est idempotente (adressage par contenu) : un lot interrompu
//!   est simplement rejoué au cycle suivant ;
//! - la boucle ne détient aucun état à sauver — tout ce qui compte est déjà
//!   dans le magasin au moment où il compte.
//!
//! Intercepter le signal (crate `ctrlc`) n'apporterait qu'un message
//! d'adieu, contre une dépendance de plus dans un binaire déployé sur tout
//! un parc — §17 exige une justification écrite pour chaque dépendance ;
//! ici, la justification est de ne pas l'ajouter.

use constat_model::DurationMs;

/// Erreurs d'analyse d'un intervalle `--every`.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum ScheduleError {
    /// La durée fournie ne correspond à aucune forme acceptée.
    #[error("durée invalide : « {0} »")]
    #[diagnostic(help("formes acceptées : 500ms, 90s, 30m (ou 30min), 6h, 7j (ou 7d)"))]
    Duration(String),
    /// Un intervalle nul ferait tourner la boucle sans reprendre son souffle.
    #[error("intervalle nul : « {0} »")]
    #[diagnostic(help("l'intervalle entre deux collectes doit être strictement positif"))]
    Zero(String),
}

/// Analyse une durée lisible : `500ms`, `90s`, `30m` (ou `30min`), `6h`,
/// `7j` (ou `7d`).
///
/// La grammaire est volontairement identique à celle de la CLI
/// (`constat-cli`, `datetime::parse_duration`) — copie locale assumée :
/// l'agent est un binaire autonome qui ne dépend pas de la CLI, et la
/// grammaire tient en dix lignes.
pub fn parse_every(s: &str) -> Result<DurationMs, ScheduleError> {
    let raw = s;
    let s = s.trim();
    let err = || ScheduleError::Duration(raw.to_string());
    let split = s.find(|c: char| !c.is_ascii_digit()).ok_or_else(err)?;
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| err())?;
    let ms = match unit.trim() {
        "ms" => n,
        "s" | "sec" => n.saturating_mul(1_000),
        "m" | "min" => n.saturating_mul(60_000),
        "h" => n.saturating_mul(3_600_000),
        "d" | "j" => n.saturating_mul(86_400_000),
        _ => return Err(err()),
    };
    if ms == 0 {
        return Err(ScheduleError::Zero(raw.to_string()));
    }
    Ok(DurationMs(ms))
}

/// Générateur congruentiel linéaire (constantes MMIX de Knuth), suffisant
/// pour désynchroniser un parc — et rien d'autre. **Non cryptographique.**
#[derive(Debug)]
pub struct Lcg(u64);

impl Lcg {
    /// Sème le générateur sur l'horloge et l'identifiant de processus :
    /// deux machines démarrées à la même seconde divergent quand même.
    pub fn from_clock() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self::seeded(millis ^ (nanos << 20) ^ (u64::from(std::process::id()) << 40))
    }

    /// Graine explicite — pour les tests, qui exigent le déterminisme.
    pub fn seeded(seed: u64) -> Self {
        Lcg(seed)
    }

    /// Tirage suivant. Les bits faibles d'un LCG sont médiocres : la sortie
    /// est mélangée par un xorshift pour que le modulo de [`jittered_ms`]
    /// ne retombe pas toujours sur les mêmes résidus.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let x = self.0;
        x ^ (x >> 31)
    }
}

/// Amplitude de la gigue, en pourcentage de l'intervalle demandé.
pub const JITTER_PERCENT: u64 = 10;

/// Intervalle avec gigue : tirage uniforme dans [90 %, 110 %] de `base_ms`.
///
/// Sous 1 ms d'amplitude (intervalles < 10 ms, en pratique les tests),
/// l'intervalle est rendu tel quel. Le léger biais du modulo est sans
/// importance ici : on étale un parc, on ne tire pas une clé.
pub fn jittered_ms(base_ms: u64, rng: &mut Lcg) -> u64 {
    let amplitude = base_ms / JITTER_PERCENT;
    if amplitude == 0 {
        return base_ms;
    }
    let offset = rng.next_u64() % (2 * amplitude + 1); // 0 ..= 2×amplitude
    base_ms - amplitude + offset
}

/// Options de la boucle planifiée.
#[derive(Debug, Clone)]
pub struct EveryOptions {
    /// Intervalle nominal entre deux débuts de cycle (gigue ±10 % appliquée
    /// à chaque attente).
    pub interval: DurationMs,
    /// **Réservée aux tests** (option cachée `--max-cycles`) : borne le
    /// nombre de cycles puis rend la main. La boucle est sinon infinie —
    /// c'est son travail. Utile aussi aux futurs tests d'intégration.
    pub max_cycles: Option<u64>,
}

/// La boucle de collecte planifiée.
///
/// `cycle(n)` est appelé immédiatement (cycle 1), puis toutes les
/// [`EveryOptions::interval`] ± 10 %. La boucle **ne s'arrête jamais sur un
/// échec de cycle** : c'est au cycle de déclarer son échec sur la sortie —
/// la continuité de la preuve prime (§4.2, un trou déclaré vaut mieux qu'un
/// agent arrêté en silence).
///
/// L'attente est un simple [`std::thread::sleep`] : aucun réveil anticipé,
/// aucun signal intercepté (voir la documentation du module pour l'arrêt).
pub fn run_every<F: FnMut(u64)>(options: &EveryOptions, mut cycle: F) {
    let mut rng = Lcg::from_clock();
    let mut n: u64 = 0;
    loop {
        n += 1;
        cycle(n);
        if let Some(max) = options.max_cycles {
            if n >= max {
                return;
            }
        }
        let wait = jittered_ms(options.interval.0, &mut rng);
        std::thread::sleep(std::time::Duration::from_millis(wait));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn duree_analysee() {
        assert_eq!(parse_every("200ms").unwrap().0, 200);
        assert_eq!(parse_every("90s").unwrap().0, 90_000);
        assert_eq!(parse_every("30m").unwrap().0, 30 * 60_000);
        assert_eq!(parse_every("30min").unwrap().0, 30 * 60_000);
        assert_eq!(parse_every("6h").unwrap().0, 6 * 3_600_000);
        assert_eq!(parse_every("7j").unwrap().0, 7 * 86_400_000);
        assert_eq!(parse_every("7d").unwrap().0, 7 * 86_400_000);
        assert_eq!(parse_every(" 6h ").unwrap().0, 6 * 3_600_000);
    }

    #[test]
    fn duree_invalide_refusee() {
        assert!(matches!(
            parse_every("six heures").unwrap_err(),
            ScheduleError::Duration(_)
        ));
        assert!(matches!(
            parse_every("6").unwrap_err(),
            ScheduleError::Duration(_)
        ));
        assert!(matches!(
            parse_every("6 heures").unwrap_err(),
            ScheduleError::Duration(_)
        ));
        assert!(matches!(
            parse_every("").unwrap_err(),
            ScheduleError::Duration(_)
        ));
    }

    #[test]
    fn duree_nulle_refusee() {
        assert!(matches!(
            parse_every("0h").unwrap_err(),
            ScheduleError::Zero(_)
        ));
        assert!(matches!(
            parse_every("0ms").unwrap_err(),
            ScheduleError::Zero(_)
        ));
    }

    /// La gigue reste bornée à ±10 % quelle que soit la graine, et varie
    /// réellement (elle ne dégénère pas en constante).
    #[test]
    fn gigue_bornee_et_variable() {
        let base: u64 = 6 * 3_600_000; // 6 h
        let lo = base - base / 10;
        let hi = base + base / 10;
        let mut rng = Lcg::seeded(0xC0FF_EE00_D15E_A5E5);
        let mut distinct = std::collections::BTreeSet::new();
        for _ in 0..10_000 {
            let v = jittered_ms(base, &mut rng);
            assert!((lo..=hi).contains(&v), "{v} hors de [{lo}, {hi}]");
            distinct.insert(v);
        }
        assert!(distinct.len() > 100, "la gigue doit réellement varier");
    }

    /// Sous 10 ms, l'amplitude entière vaut zéro : intervalle rendu tel quel.
    #[test]
    fn gigue_nulle_sur_tres_petit_intervalle() {
        let mut rng = Lcg::seeded(42);
        assert_eq!(jittered_ms(5, &mut rng), 5);
    }

    /// Le mode --every avec un intervalle très court et `--max-cycles` :
    /// le nombre de cycles est exact, et les attentes ont bien eu lieu
    /// (2 attentes d'au moins 180 ms entre 3 cycles).
    #[test]
    fn boucle_bornee_par_max_cycles() {
        let options = EveryOptions {
            interval: parse_every("200ms").unwrap(),
            max_cycles: Some(3),
        };
        let mut cycles = Vec::new();
        let debut = std::time::Instant::now();
        run_every(&options, |n| cycles.push(n));
        let ecoule = debut.elapsed();
        assert_eq!(cycles, vec![1, 2, 3]);
        // 2 attentes ≥ 90 % de 200 ms ; pas de borne haute (machine chargée).
        assert!(
            ecoule >= std::time::Duration::from_millis(350),
            "attentes trop courtes : {ecoule:?}"
        );
    }

    /// Un seul cycle demandé : aucune attente après le dernier cycle.
    #[test]
    fn boucle_un_seul_cycle() {
        let options = EveryOptions {
            interval: parse_every("1h").unwrap(), // dormirait 1 h si la boucle attendait
            max_cycles: Some(1),
        };
        let mut compte = 0u64;
        run_every(&options, |_| compte += 1);
        assert_eq!(compte, 1);
    }
}
