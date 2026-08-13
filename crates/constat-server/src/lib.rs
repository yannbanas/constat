//! # constat-server — bibliothèque
//!
//! Réception des poussées d'agents, exposée en bibliothèque pour que les
//! tests d'intégration démarrent le **vrai** serveur en processus — le
//! binaire `constat-server` n'est qu'une couche d'arguments au-dessus.
//!
//! # Propriété d'architecture (§17) : aucun chemin de retour
//!
//! Compromettre ce serveur ne donne aucun moyen d'agir sur les machines
//! auditées, parce qu'il n'en a aucun — c'est une propriété de construction :
//!
//! - aucun module de ce crate n'initie de connexion sortante : le seul appel
//!   réseau est `TcpListener::bind` dans [`serve`], les agents poussent ;
//! - la réponse à une poussée est un [`receive::Receipt`] — des compteurs et
//!   une empreinte, aucun type de cette interface ne peut transporter une
//!   instruction, une configuration ou du code vers l'agent ;
//! - le serveur ne connaît des agents que leur certificat client et leur clé
//!   publique de signature.

pub mod inventory;
pub mod receive;
pub mod serve;
