# db_manager.py

import sqlite3
import os
from typing import List, Tuple, Optional
from dataclasses import dataclass

MAIN_MASTER_DB = "vapt_master.db"
VULN_DB = "vulnerabilities.db"

@dataclass
class Vulnerability:
    id: int
    name: str
    vapt_type: str
    severity: str
    cvss_score: Optional[float]
    description: Optional[str]
    impact: Optional[str]
    remediation: Optional[str]
    references_text: Optional[str]

    @classmethod
    def from_tuple(cls, row: Tuple) -> "Vulnerability":
        return cls(
            id=row[0], name=row[1], vapt_type=row[2], severity=row[3],
            cvss_score=float(row[4]) if row[4] not in (None, "") else None,
            description=row[5], impact=row[6], remediation=row[7], references_text=row[8]
        )

def _create_vulnerabilities_table(db_file: str) -> None:
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                vapt_type TEXT,
                severity TEXT,
                cvss_score REAL,         -- changed to REAL for cvss
                description TEXT,
                impact TEXT,
                remediation TEXT,
                references_text TEXT
            )
        """)
        # Add migration if done before
        c.execute("PRAGMA table_info(vulnerabilities)")
        cols = [x[1] for x in c.fetchall()]
        if 'cvss_score' not in cols:
            c.execute("ALTER TABLE vulnerabilities ADD COLUMN cvss_score REAL")
        conn.commit()
    finally:
        conn.close()

def create_main_db(db_file: str) -> None:
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS companies (
                company_name TEXT PRIMARY KEY
            )
        """)
        conn.commit()
    finally:
        conn.close()
    _create_vulnerabilities_table(VULN_DB)

def ensure_company_tables(db_file: str, cursor) -> None:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS company_vulns (
            vuln_id INTEGER,
            vuln_name TEXT,
            vapt_type TEXT,
            severity TEXT,
            cvss_score REAL,
            evidence TEXT,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
        )
    """)
    # Add migration if missing
    cursor.execute("PRAGMA table_info(company_vulns)")
    cols = [x[1] for x in cursor.fetchall()]
    if "cvss_score" not in cols:
        cursor.execute("ALTER TABLE company_vulns ADD COLUMN cvss_score REAL")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS company_vuln_targets (
            vuln_id INTEGER,
            target TEXT,
            target_class TEXT,
            port TEXT,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
        )
    """)
    cursor.execute("PRAGMA table_info(company_vuln_targets)")
    cols2 = [x[1] for x in cursor.fetchall()]
    if "port" not in cols2:
        cursor.execute("ALTER TABLE company_vuln_targets ADD COLUMN port TEXT")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS company_classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_name TEXT UNIQUE
        )
    """)

def create_company_db(company_name: str) -> None:
    db_file = f"{company_name}.db"
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        ensure_company_tables(db_file, c)
        conn.commit()
    finally:
        conn.close()

def migrate_all_company_dbs():
    # Optionally add a migration function
    from glob import glob
    for f in glob("*.db"):
        if f not in [MAIN_MASTER_DB, VULN_DB]:
            conn = sqlite3.connect(f)
            try:
                c = conn.cursor()
                ensure_company_tables(f, c)
                conn.commit()
            finally:
                conn.close()

# ------- Master Vulnerabilities Management -------
def add_vulnerability(
    db_file: str,
    name: str,
    vapt_type: str,
    severity: str,
    cvss_score: Optional[float],
    description: str,
    impact: str,
    remediation: str,
    references_text: str,
) -> None:
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO vulnerabilities (name, vapt_type, severity, cvss_score, description, impact, remediation, references_text) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (name, vapt_type, severity, cvss_score, description, impact, remediation, references_text),
        )
        conn.commit()
    finally:
        conn.close()

def get_all_vulnerabilities(db_file: str) -> List[Vulnerability]:
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM vulnerabilities ORDER BY id DESC")
        return [Vulnerability.from_tuple(row) for row in c.fetchall()]
    finally:
        conn.close()

def get_vulnerability_by_name(db_file: str, name: str) -> Optional[Vulnerability]:
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM vulnerabilities WHERE name = ?", (name,))
        row = c.fetchone()
        return Vulnerability.from_tuple(row) if row else None
    finally:
        conn.close()

def get_vulnerability_by_id(db_file: str, vuln_id: int) -> Optional[Vulnerability]:
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
        row = c.fetchone()
        return Vulnerability.from_tuple(row) if row else None
    finally:
        conn.close()

def update_vulnerability(
    db_file: str,
    vuln_id: int,
    name: str,
    vapt_type: str,
    severity: str,
    cvss_score: Optional[float],
    description: str,
    impact: str,
    remediation: str,
    references_text: str,
) -> None:
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute(
            """
            UPDATE vulnerabilities
            SET name = ?, vapt_type = ?, severity = ?, cvss_score = ?,
                description = ?, impact = ?, remediation = ?, references_text = ?
            WHERE id = ?
            """,
            (name, vapt_type, severity, cvss_score, description, impact, remediation, references_text, vuln_id),
        )
        conn.commit()
    finally:
        conn.close()

def delete_vulnerability_by_id(db_file: str, vuln_id: int) -> None:
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
        conn.commit()
    finally:
        conn.close()

# ------- Company + Target Management -------
def get_company_list() -> List[str]:
    conn = sqlite3.connect(MAIN_MASTER_DB)
    try:
        c = conn.cursor()
        c.execute("SELECT company_name FROM companies")
        return [row[0] for row in c.fetchall()]
    finally:
        conn.close()

def add_company(db_file: str, company_name: str) -> None:
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("INSERT INTO companies (company_name) VALUES (?)", (company_name,))
        conn.commit()
    finally:
        conn.close()
    create_company_db(company_name)

def delete_company_db_and_data(company_name: str) -> None:
    db_file = f"{company_name}.db"
    if os.path.exists(db_file):
        os.remove(db_file)
    conn = sqlite3.connect(MAIN_MASTER_DB)
    try:
        c = conn.cursor()
        c.execute("DELETE FROM companies WHERE company_name = ?", (company_name,))
        conn.commit()
    finally:
        conn.close()

def add_or_append_company_data(
    company: str,
    vuln_id: int,
    vuln_name: str,
    severity: str,
    vapt_type: str,
    evidence: str,
    targets_info: List[Tuple[str, str]],
    cvss_score: Optional[float] = None,    # <-- Now keyword-only, optional, default None
) -> None:
    db_file = f"{company}.db"
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM company_vulns WHERE vuln_id = ?", (vuln_id,))
        exists = c.fetchone()
        if exists:
            c.execute(
                "UPDATE company_vulns SET evidence = ?, vuln_name = ?, severity = ?, vapt_type = ?, cvss_score = ? WHERE vuln_id = ?",
                (evidence, vuln_name, severity, vapt_type, cvss_score, vuln_id),
            )
            c.execute("DELETE FROM company_vuln_targets WHERE vuln_id = ?", (vuln_id,))
        else:
            c.execute(
                "INSERT INTO company_vulns (vuln_id, vuln_name, severity, vapt_type, cvss_score, evidence) VALUES (?, ?, ?, ?, ?, ?)",
                (vuln_id, vuln_name, severity, vapt_type, cvss_score, evidence),
            )
        c.executemany(
            "INSERT INTO company_vuln_targets (vuln_id, target, target_class, port) VALUES (?, ?, ?, ?)",
            [(vuln_id, t_name, t_class, t_port) for t_name, t_class, t_port in targets_info],
        )
        conn.commit()
    finally:
        conn.close()

def get_vuln_data_for_company(company: str, vuln_id: int) -> Tuple[Optional[Tuple], List[Tuple]]:
    db_file = f"{company}.db"
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM company_vulns WHERE vuln_id = ?", (vuln_id,))
        vuln_data = c.fetchone()
        targets = []
        if vuln_data:
            c.execute(
                "SELECT target, target_class, port FROM company_vuln_targets WHERE vuln_id = ?",
                (vuln_id,),
            )
            targets = c.fetchall()
        return vuln_data, targets
    finally:
        conn.close()

def delete_company_vuln(company: str, vuln_id: int) -> None:
    db_file = f"{company}.db"
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("DELETE FROM company_vulns WHERE vuln_id = ?", (vuln_id,))
        c.execute("DELETE FROM company_vuln_targets WHERE vuln_id = ?", (vuln_id,))
        conn.commit()
    finally:
        conn.close()

def get_all_company_vulns(company: str) -> List[dict]:
    db_file = f"{company}.db"
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("SELECT vuln_id, vuln_name, severity, vapt_type, cvss_score, evidence FROM company_vulns ORDER BY cvss_score DESC, severity DESC, vuln_name ASC")
        company_vulns = c.fetchall()
        vulns_with_targets = []
        for v_id, v_name, severity, v_type, cvss, evidence in company_vulns:
            c.execute(
                "SELECT target, target_class, port FROM company_vuln_targets WHERE vuln_id = ?",
                (v_id,),
            )
            targets = c.fetchall()  # (target, class, port)
            vulns_with_targets.append({
                "vuln_id": v_id,
                "vuln_name": v_name,
                "severity": severity,
                "vapt_type": v_type,
                "cvss_score": cvss,
                "evidence": evidence,
                "targets": targets,
            })
        return vulns_with_targets
    finally:
        conn.close()

def get_vuln_data_for_report(company: str, vapt_type: str) -> Tuple[dict, dict]:
    db_file = f"{company}.db"
    conn = sqlite3.connect(db_file)
    vuln_details = {}
    targets_data = {}
    try:
        c1 = conn.cursor()
        c1.execute(
            "SELECT vuln_id, vuln_name, severity, vapt_type, cvss_score, evidence FROM company_vulns WHERE vapt_type = ? ORDER BY cvss_score DESC, severity DESC, vuln_name ASC",
            (vapt_type,),
        )
        company_vulns = c1.fetchall()
        ids_needed = [row[0] for row in company_vulns]
        master_map = {}
        if ids_needed:
            conn_master = sqlite3.connect(VULN_DB)
            try:
                c2 = conn_master.cursor()
                placeholders = ",".join("?" for _ in ids_needed)
                c2.execute(
                    f"SELECT id, description, impact, remediation, references_text, cvss_score FROM vulnerabilities WHERE id IN ({placeholders})",
                    ids_needed,
                )
                for mid, desc, imp, rem, ref, cvss in c2.fetchall():
                    master_map[mid] = (desc or "", imp or "", rem or "", ref or "", cvss)
            finally:
                conn_master.close()
        for v_id, v_name, severity, v_type, cvss_score, evidence in company_vulns:
            desc, imp, rem, ref, master_cvss = master_map.get(v_id, ("", "", "", "", None))
            vuln_details[v_id] = {
                "vuln_name": v_name,
                "severity": severity,
                "vapt_type": v_type,
                "cvss_score": cvss_score if cvss_score is not None else master_cvss,
                "evidence": evidence,
                "description": desc,
                "impact": imp,
                "remediation": rem,
                "references": ref,
            }
        c1.execute("SELECT vuln_id, target, target_class, port FROM company_vuln_targets")
        for v_id, target, t_class, port in c1.fetchall():
            if v_id not in targets_data:
                targets_data[v_id] = []
            targets_data[v_id].append((target, t_class, port))
    finally:
        conn.close()
    return vuln_details, targets_data

def get_company_classes(company: str) -> List[str]:
    db_file = f"{company}.db"
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("SELECT class_name FROM company_classes ORDER BY class_name ASC")
        return [row[0] for row in c.fetchall()]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()

def add_company_class(company: str, class_name: str) -> None:
    db_file = f"{company}.db"
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO company_classes (class_name) VALUES (?)", (class_name,))
        conn.commit()
    finally:
        conn.close()
