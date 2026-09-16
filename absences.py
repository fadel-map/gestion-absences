"""
Application de gestion des absences des étudiants en TD
---------------------------------------------------------
- Connexion / création de compte avec mot de passe sécurisé
- Sauvegarde persistante via SQLite3 (survit aux redémarrages de Streamlit)
- 3 sections : Enregistrement d'absence / Absences sauvegardées / Statistiques
"""

import streamlit as st
import hashlib
import secrets
import re
from datetime import date, datetime
import pandas as pd
from sqlalchemy import create_engine, text

# ----------------------------------------------------------------------
# CONFIGURATION GENERALE
# ----------------------------------------------------------------------
GROUPES_TD = [f"Groupe {i}" for i in range(1, 7)]
NIVEAUX_ETUDE = ["Licence 1", "Licence 2", "Licence 3", "Master 1", "Master 2"]

st.set_page_config(page_title="Gestion des absences", page_icon="📋", layout="wide")

# ----------------------------------------------------------------------
# BASE DE DONNEES (Postgres hébergé — persiste entre machines et redéploiements)
# ----------------------------------------------------------------------
@st.cache_resource
def get_engine():
    """
    Connexion à la base Postgres hébergée (Supabase, Neon, etc.).
    L'URL de connexion doit être définie dans .streamlit/secrets.toml :

    [postgres]
    url = "postgresql://utilisateur:motdepasse@hote:5432/nom_de_la_base"
    """
    if "postgres" not in st.secrets or "url" not in st.secrets["postgres"]:
        st.error(
            "⚠️ Aucune base de données configurée. Ajoute ta chaîne de connexion "
            "dans les 'Secrets' de l'application (voir les instructions fournies)."
        )
        st.stop()
    return create_engine(st.secrets["postgres"]["url"], pool_pre_ping=True)


def init_db():
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'utilisateur',
                created_at TEXT NOT NULL
            )
        """))
        # Migration : si la table 'users' existait déjà sans la colonne 'role'
        conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'utilisateur'"
        ))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS absences (
                id SERIAL PRIMARY KEY,
                prenom TEXT NOT NULL,
                nom TEXT NOT NULL,
                date_absence TEXT NOT NULL,
                niveau TEXT NOT NULL DEFAULT 'Non précisé',
                groupe TEXT NOT NULL,
                motif TEXT,
                enregistre_par TEXT,
                date_enregistrement TEXT NOT NULL
            )
        """))
        # Migration : si la table 'absences' existait déjà sans la colonne 'niveau'
        conn.execute(text(
            "ALTER TABLE absences ADD COLUMN IF NOT EXISTS niveau TEXT NOT NULL DEFAULT 'Non précisé'"
        ))


# ----------------------------------------------------------------------
# SECURITE DES MOTS DE PASSE
# ----------------------------------------------------------------------
def hash_password(password: str, salt: str) -> str:
    """Hachage sécurisé avec PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    ).hex()


def check_password_strength(password: str) -> list:
    """Retourne la liste des règles non respectées (vide = mot de passe valide)."""
    errors = []
    if len(password) < 8:
        errors.append("au moins 8 caractères")
    if not re.search(r"[A-Z]", password):
        errors.append("au moins une majuscule")
    if not re.search(r"[a-z]", password):
        errors.append("au moins une minuscule")
    if not re.search(r"[0-9]", password):
        errors.append("au moins un chiffre")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\+=]", password):
        errors.append("au moins un caractère spécial (!@#$%...)")
    return errors


def get_registration_code() -> str:
    """Code d'inscription requis, défini dans secrets.toml sous [app] registration_code."""
    try:
        return st.secrets["app"]["registration_code"]
    except (KeyError, FileNotFoundError):
        return None


def create_user(username: str, password: str) -> tuple:
    engine = get_engine()
    with engine.begin() as conn:
        existing = conn.execute(
            text("SELECT id FROM users WHERE username = :u"), {"u": username}
        ).fetchone()
        if existing:
            return False, "Ce nom d'utilisateur existe déjà."

        salt = secrets.token_hex(16)
        pwd_hash = hash_password(password, salt)
        conn.execute(
            text("""INSERT INTO users (username, password_hash, salt, role, created_at)
                     VALUES (:u, :h, :s, 'utilisateur', :c)"""),
            {"u": username, "h": pwd_hash, "s": salt, "c": datetime.now().isoformat()},
        )
    return True, "Compte créé avec succès."


def verify_user(username: str, password: str):
    """Retourne le rôle ('utilisateur' ou 'admin') si les identifiants sont corrects, sinon None."""
    engine = get_engine()
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT password_hash, salt, role FROM users WHERE username = :u"),
            {"u": username},
        ).fetchone()
    if not row:
        return None
    stored_hash, salt, role = row
    if hash_password(password, salt) == stored_hash:
        return role
    return None


# ----------------------------------------------------------------------
# GESTION DES ABSENCES
# ----------------------------------------------------------------------
def ajouter_absence(prenom, nom, date_absence, niveau, groupe, motif, enregistre_par):
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""INSERT INTO absences
                     (prenom, nom, date_absence, niveau, groupe, motif, enregistre_par, date_enregistrement)
                     VALUES (:p, :n, :d, :niv, :g, :m, :e, :t)"""),
            {
                "p": prenom.strip(), "n": nom.strip(), "d": str(date_absence),
                "niv": niveau, "g": groupe, "m": motif.strip(), "e": enregistre_par,
                "t": datetime.now().isoformat(),
            },
        )


def charger_absences() -> pd.DataFrame:
    engine = get_engine()
    with engine.connect() as conn:
        df = pd.read_sql_query(
            text("""SELECT id, prenom, nom, date_absence, niveau, groupe, motif,
                            enregistre_par, date_enregistrement
                     FROM absences ORDER BY date_absence DESC"""),
            conn,
        )
    return df


def supprimer_absence(absence_id: int):
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM absences WHERE id = :i"), {"i": absence_id})


def modifier_absence(absence_id: int, prenom, nom, date_absence, niveau, groupe, motif):
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("""UPDATE absences
                     SET prenom = :p, nom = :n, date_absence = :d,
                         niveau = :niv, groupe = :g, motif = :m
                     WHERE id = :i"""),
            {
                "p": prenom.strip(), "n": nom.strip(), "d": str(date_absence),
                "niv": niveau, "g": groupe, "m": motif.strip(), "i": absence_id,
            },
        )


# ----------------------------------------------------------------------
# INITIALISATION
# ----------------------------------------------------------------------
init_db()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "role" not in st.session_state:
    st.session_state.role = None


# ----------------------------------------------------------------------
# PAGE : CONNEXION / CREATION DE COMPTE
# ----------------------------------------------------------------------
def page_auth():
    st.title("📋 Gestion des absences — Connexion")

    tab_connexion, tab_creation = st.tabs(["🔑 Connexion", "🆕 Créer un compte"])

    with tab_connexion:
        with st.form("form_connexion"):
            username = st.text_input("Nom d'utilisateur", key="login_user")
            password = st.text_input("Mot de passe", type="password", key="login_pwd")
            submit = st.form_submit_button("Se connecter")

        if submit:
            if not username or not password:
                st.error("Veuillez remplir tous les champs.")
            else:
                role = verify_user(username, password)
                if role:
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.session_state.role = role
                    st.success("Connexion réussie !")
                    st.rerun()
                else:
                    st.error("Nom d'utilisateur ou mot de passe incorrect.")

    with tab_creation:
        st.caption(
            "Le mot de passe doit contenir : 8 caractères minimum, une majuscule, "
            "une minuscule, un chiffre et un caractère spécial."
        )
        required_code = get_registration_code()
        with st.form("form_creation"):
            if required_code:
                access_code = st.text_input(
                    "Code d'inscription",
                    type="password",
                    help="Code fourni par l'enseignant responsable, requis pour créer un compte.",
                )
            new_username = st.text_input("Choisir un nom d'utilisateur", key="new_user")
            new_password = st.text_input("Choisir un mot de passe", type="password", key="new_pwd")
            confirm_password = st.text_input("Confirmer le mot de passe", type="password", key="confirm_pwd")
            submit_new = st.form_submit_button("Créer le compte")

        if submit_new:
            if required_code and access_code != required_code:
                st.error("Code d'inscription incorrect.")
            elif not new_username or not new_password:
                st.error("Veuillez remplir tous les champs.")
            elif new_password != confirm_password:
                st.error("Les deux mots de passe ne correspondent pas.")
            else:
                errors = check_password_strength(new_password)
                if errors:
                    st.error("Le mot de passe doit contenir : " + ", ".join(errors) + ".")
                else:
                    success, message = create_user(new_username, new_password)
                    if success:
                        st.success(message + " Vous pouvez maintenant vous connecter.")
                    else:
                        st.error(message)


# ----------------------------------------------------------------------
# PAGE 1 : ENREGISTREMENT D'ABSENCE
# ----------------------------------------------------------------------
def page_enregistrement():
    st.header("✏️ Enregistrer une absence")

    with st.form("form_absence", clear_on_submit=True):
        col1, col2 = st.columns(2)
        with col1:
            prenom = st.text_input("Prénom de l'étudiant")
            date_absence = st.date_input("Date de l'absence", value=date.today())
            niveau = st.selectbox("Niveau d'étude", NIVEAUX_ETUDE)
        with col2:
            nom = st.text_input("Nom de l'étudiant")
            groupe = st.selectbox("Groupe de TD", GROUPES_TD)

        motif = st.text_area("Motif de l'absence", placeholder="Ex : maladie, transport, sans justification...")

        submit = st.form_submit_button("✅ Enregistrer l'absence", use_container_width=True)

    if submit:
        if not prenom.strip() or not nom.strip():
            st.error("Le prénom et le nom de l'étudiant sont obligatoires.")
        else:
            ajouter_absence(prenom, nom, date_absence, niveau, groupe, motif, st.session_state.username)
            st.success(f"Absence de {prenom} {nom} ({niveau}, {groupe}) enregistrée avec succès ✅")


# ----------------------------------------------------------------------
# PAGE 2 : ABSENCES SAUVEGARDEES
# ----------------------------------------------------------------------
def page_absences_sauvegardees():
    st.header("📁 Absences sauvegardées")

    df = charger_absences()

    if df.empty:
        st.info("Aucune absence enregistrée pour le moment.")
        return

    # Filtres
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        filtre_niveau = st.multiselect("Filtrer par niveau", NIVEAUX_ETUDE)
    with col2:
        filtre_groupe = st.multiselect("Filtrer par groupe", GROUPES_TD)
    with col3:
        recherche_nom = st.text_input("Rechercher par nom/prénom")
    with col4:
        tri = st.selectbox("Trier par", ["Date (récent → ancien)", "Date (ancien → récent)", "Nom"])

    df_affiche = df.copy()
    if filtre_niveau:
        df_affiche = df_affiche[df_affiche["niveau"].isin(filtre_niveau)]
    if filtre_groupe:
        df_affiche = df_affiche[df_affiche["groupe"].isin(filtre_groupe)]
    if recherche_nom:
        mask = (
            df_affiche["prenom"].str.contains(recherche_nom, case=False, na=False)
            | df_affiche["nom"].str.contains(recherche_nom, case=False, na=False)
        )
        df_affiche = df_affiche[mask]

    if tri == "Date (récent → ancien)":
        df_affiche = df_affiche.sort_values("date_absence", ascending=False)
    elif tri == "Date (ancien → récent)":
        df_affiche = df_affiche.sort_values("date_absence", ascending=True)
    else:
        df_affiche = df_affiche.sort_values(["nom", "prenom"])

    df_affiche = df_affiche.rename(columns={
        "id": "ID", "prenom": "Prénom", "nom": "Nom", "date_absence": "Date",
        "niveau": "Niveau", "groupe": "Groupe", "motif": "Motif",
        "enregistre_par": "Enregistré par", "date_enregistrement": "Horodatage",
    })

    st.dataframe(df_affiche, use_container_width=True, hide_index=True)
    st.caption(f"Total : {len(df_affiche)} absence(s) affichée(s) sur {len(df)} au total.")

    # Modification et suppression d'une absence (réservées aux administrateurs)
    if st.session_state.role == "admin":
        with st.expander("✏️ Modifier une absence (admin)"):
            options_mod = {
                f"#{row.id} — {row.prenom} {row.nom} ({row.date_absence}, {row.niveau}, {row.groupe})": row.id
                for row in df.itertuples()
            }
            choix_mod = st.selectbox("Choisir l'absence à modifier", list(options_mod.keys()), key="select_modif")
            id_mod = options_mod[choix_mod]
            ligne = df[df["id"] == id_mod].iloc[0]

            with st.form("form_modif_absence"):
                mcol1, mcol2 = st.columns(2)
                with mcol1:
                    m_prenom = st.text_input("Prénom", value=ligne["prenom"])
                    m_date = st.date_input(
                        "Date de l'absence",
                        value=pd.to_datetime(ligne["date_absence"]).date(),
                    )
                    m_niveau = st.selectbox(
                        "Niveau d'étude", NIVEAUX_ETUDE,
                        index=NIVEAUX_ETUDE.index(ligne["niveau"]) if ligne["niveau"] in NIVEAUX_ETUDE else 0,
                    )
                with mcol2:
                    m_nom = st.text_input("Nom", value=ligne["nom"])
                    m_groupe = st.selectbox(
                        "Groupe de TD", GROUPES_TD,
                        index=GROUPES_TD.index(ligne["groupe"]) if ligne["groupe"] in GROUPES_TD else 0,
                    )
                m_motif = st.text_area("Motif", value=ligne["motif"] or "")

                submit_mod = st.form_submit_button("💾 Enregistrer les modifications", use_container_width=True)

            if submit_mod:
                if not m_prenom.strip() or not m_nom.strip():
                    st.error("Le prénom et le nom sont obligatoires.")
                else:
                    modifier_absence(id_mod, m_prenom, m_nom, m_date, m_niveau, m_groupe, m_motif)
                    st.success("Absence modifiée avec succès ✅")
                    st.rerun()

        with st.expander("🗑️ Supprimer une absence (admin)"):
            if not df.empty:
                options = {
                    f"#{row.id} — {row.prenom} {row.nom} ({row.date_absence}, {row.niveau}, {row.groupe})": row.id
                    for row in df.itertuples()
                }
                choix = st.selectbox("Choisir l'absence à supprimer", list(options.keys()))
                if st.button("Confirmer la suppression", type="primary"):
                    supprimer_absence(options[choix])
                    st.success("Absence supprimée.")
                    st.rerun()
    else:
        st.caption("🔒 Seul un administrateur peut modifier ou supprimer une absence.")

    # Export CSV
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Télécharger toutes les absences (CSV)", csv, "absences.csv", "text/csv")


# ----------------------------------------------------------------------
# PAGE 3 : STATISTIQUES
# ----------------------------------------------------------------------
def page_statistiques():
    st.header("📊 Statistiques des absences")

    df = charger_absences()
    if df.empty:
        st.info("Aucune donnée disponible pour générer des statistiques.")
        return

    df["date_absence"] = pd.to_datetime(df["date_absence"], errors="coerce")

    total = len(df)
    nb_etudiants = df[["prenom", "nom"]].drop_duplicates().shape[0]
    groupe_top = df["groupe"].value_counts().idxmax() if not df.empty else "-"

    col1, col2, col3 = st.columns(3)
    col1.metric("Total absences", total)
    col2.metric("Étudiants concernés", nb_etudiants)
    col3.metric("Groupe le plus touché", groupe_top)

    st.divider()

    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("Absences par niveau d'étude")
        par_niveau = df["niveau"].value_counts().reindex(NIVEAUX_ETUDE, fill_value=0)
        st.bar_chart(par_niveau)

    with col_b:
        st.subheader("Absences par groupe de TD")
        par_groupe = df["groupe"].value_counts().reindex(GROUPES_TD, fill_value=0)
        st.bar_chart(par_groupe)

    st.divider()

    st.subheader("Absences par motif")
    motifs = df["motif"].replace("", "Non précisé").fillna("Non précisé")
    par_motif = motifs.value_counts()
    st.bar_chart(par_motif)

    st.divider()

    st.subheader("Évolution des absences dans le temps")
    par_date = df.groupby(df["date_absence"].dt.date).size()
    par_date.index = pd.to_datetime(par_date.index)
    st.line_chart(par_date)

    st.divider()

    st.subheader("🏆 Étudiants les plus absents")
    par_etudiant = (
        df.groupby(["prenom", "nom"]).size().reset_index(name="Nombre d'absences")
        .sort_values("Nombre d'absences", ascending=False).head(10)
    )
    par_etudiant.index = range(1, len(par_etudiant) + 1)
    st.dataframe(par_etudiant, use_container_width=True)


# ----------------------------------------------------------------------
# APPLICATION PRINCIPALE
# ----------------------------------------------------------------------
def main_app():
    with st.sidebar:
        st.title("📋 Menu")
        badge = "🛡️ admin" if st.session_state.role == "admin" else "👤 utilisateur"
        st.write(f"Connecté en tant que **{st.session_state.username}** ({badge})")
        page = st.radio(
            "Navigation",
            ["📝 Enregistrement d'absence", "📁 Absences sauvegardées", "📊 Statistiques"],
        )
        st.divider()
        if st.button("🚪 Se déconnecter", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.username = None
            st.session_state.role = None
            st.rerun()

    if page == "📝 Enregistrement d'absence":
        page_enregistrement()
    elif page == "📁 Absences sauvegardées":
        page_absences_sauvegardees()
    else:
        page_statistiques()


# ----------------------------------------------------------------------
# POINT D'ENTREE
# ----------------------------------------------------------------------
if st.session_state.logged_in:
    main_app()
else:
    page_auth()