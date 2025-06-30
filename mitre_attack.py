import json
import sqlite3
from typing import List, Optional, Tuple
from pathlib import Path
import logging
from models import AttackTactic, AttackTechnique


class MitreAttackFramework:

    def __init__(self, db_path: str = "data/mitre_attack.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._ensure_database()

    def _ensure_database(self):
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        if not Path(self.db_path).exists():
            self._initialize_database()
            self._populate_database()
    
    def _initialize_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tactics (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                external_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS techniques (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                platforms TEXT,
                data_sources TEXT,
                mitigations TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS technique_tactics (
                technique_id TEXT,
                tactic_id TEXT,
                PRIMARY KEY (technique_id, tactic_id),
                FOREIGN KEY (technique_id) REFERENCES techniques (id),
                FOREIGN KEY (tactic_id) REFERENCES tactics (id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sub_techniques (
                id TEXT PRIMARY KEY,
                parent_technique_id TEXT,
                name TEXT NOT NULL,
                description TEXT,
                FOREIGN KEY (parent_technique_id) REFERENCES techniques (id)
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_technique_name ON techniques (name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tactic_name ON tactics (name)")

        conn.commit()
        conn.close()
    
    def _populate_database(self):
        tactics_data = [
            {
                "id": "TA0001",
                "name": "Initial Access",
                "description": "The adversary is trying to get into your network.",
                "external_id": "TA0001"
            },
            {
                "id": "TA0002", 
                "name": "Execution",
                "description": "The adversary is trying to run malicious code.",
                "external_id": "TA0002"
            },
            {
                "id": "TA0003",
                "name": "Persistence",
                "description": "The adversary is trying to maintain their foothold.",
                "external_id": "TA0003"
            },
            {
                "id": "TA0004",
                "name": "Privilege Escalation",
                "description": "The adversary is trying to gain higher-level permissions.",
                "external_id": "TA0004"
            },
            {
                "id": "TA0005",
                "name": "Defense Evasion",
                "description": "The adversary is trying to avoid being detected.",
                "external_id": "TA0005"
            },
            {
                "id": "TA0006",
                "name": "Credential Access",
                "description": "The adversary is trying to steal account names and passwords.",
                "external_id": "TA0006"
            },
            {
                "id": "TA0007",
                "name": "Discovery",
                "description": "The adversary is trying to figure out your environment.",
                "external_id": "TA0007"
            },
            {
                "id": "TA0008",
                "name": "Lateral Movement",
                "description": "The adversary is trying to move through your environment.",
                "external_id": "TA0008"
            },
            {
                "id": "TA0009",
                "name": "Collection",
                "description": "The adversary is trying to gather data of interest.",
                "external_id": "TA0009"
            },
            {
                "id": "TA0010",
                "name": "Exfiltration",
                "description": "The adversary is trying to steal data.",
                "external_id": "TA0010"
            },
            {
                "id": "TA0011",
                "name": "Command and Control",
                "description": "The adversary is trying to communicate with compromised systems.",
                "external_id": "TA0011"
            },
            {
                "id": "TA0040",
                "name": "Impact",
                "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
                "external_id": "TA0040"
            }
        ]

        techniques_data = [
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Command", "Process", "Script"],
                "mitigations": ["Code Signing", "Execution Prevention"],
                "tactics": ["TA0002"]  # Execution
            },
            {
                "id": "T1566",
                "name": "Phishing",
                "description": "Adversaries may send phishing messages to gain access to victim systems.",
                "platforms": ["Windows", "Linux", "macOS", "Office 365", "SaaS", "Google Workspace"],
                "data_sources": ["Application Log", "Email Gateway", "File"],
                "mitigations": ["User Training", "Email Security"],
                "tactics": ["TA0001"]  # Initial Access
            },
            {
                "id": "T1055",
                "name": "Process Injection",
                "description": "Adversaries may inject code into processes in order to evade process-based defenses.",
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Process", "Windows Registry"],
                "mitigations": ["Behavior Prevention on Endpoint"],
                "tactics": ["TA0004", "TA0005"]  # Privilege Escalation, Defense Evasion
            },
            {
                "id": "T1003",
                "name": "OS Credential Dumping",
                "description": "Adversaries may attempt to dump credentials to obtain account login information.",
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Command", "File", "Process"],
                "mitigations": ["Password Policies", "Privileged Account Management"],
                "tactics": ["TA0006"]  # Credential Access
            },
            {
                "id": "T1082",
                "name": "System Information Discovery",
                "description": "An adversary may attempt to get detailed information about the operating system and hardware.",
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Command", "Process"],
                "mitigations": [],
                "tactics": ["TA0007"]
            }
        ]

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for tactic in tactics_data:
            cursor.execute("""
                INSERT OR REPLACE INTO tactics (id, name, description, external_id)
                VALUES (?, ?, ?, ?)
            """, (tactic["id"], tactic["name"], tactic["description"], tactic["external_id"]))

        for technique in techniques_data:
            cursor.execute("""
                INSERT OR REPLACE INTO techniques (id, name, description, platforms, data_sources, mitigations)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                technique["id"],
                technique["name"],
                technique["description"],
                json.dumps(technique["platforms"]),
                json.dumps(technique["data_sources"]),
                json.dumps(technique["mitigations"])
            ))

            for tactic_id in technique["tactics"]:
                cursor.execute("""
                    INSERT OR REPLACE INTO technique_tactics (technique_id, tactic_id)
                    VALUES (?, ?)
                """, (technique["id"], tactic_id))

        conn.commit()
        conn.close()
        self.logger.info("MITRE ATT&CK database populated with sample data")
    
    def get_all_tactics(self) -> List[AttackTactic]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT id, name, description, external_id FROM tactics ORDER BY id")
        rows = cursor.fetchall()
        conn.close()

        return [
            AttackTactic(
                id=row[0],
                name=row[1],
                description=row[2] or "",
                external_id=row[3] or ""
            ) for row in rows
        ]

    def get_all_techniques(self) -> List[AttackTechnique]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT t.id, t.name, t.description, t.platforms, t.data_sources, t.mitigations,
                   GROUP_CONCAT(tt.tactic_id) as tactic_ids
            FROM techniques t
            LEFT JOIN technique_tactics tt ON t.id = tt.technique_id
            GROUP BY t.id, t.name, t.description, t.platforms, t.data_sources, t.mitigations
            ORDER BY t.id
        """)
        rows = cursor.fetchall()
        conn.close()

        techniques = []
        for row in rows:
            tactic_ids = row[6].split(",") if row[6] else []
            techniques.append(AttackTechnique(
                id=row[0],
                name=row[1],
                description=row[2] or "",
                tactic_ids=tactic_ids,
                platforms=json.loads(row[3]) if row[3] else [],
                data_sources=json.loads(row[4]) if row[4] else [],
                mitigations=json.loads(row[5]) if row[5] else []
            ))

        return techniques
    
    def search_techniques_by_keywords(self, keywords: List[str]) -> List[Tuple[AttackTechnique, float]]:
        techniques = self.get_all_techniques()
        results = []

        for technique in techniques:
            score = self._calculate_keyword_match_score(technique, keywords)
            if score > 0:
                results.append((technique, score))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def _calculate_keyword_match_score(self, technique: AttackTechnique, keywords: List[str]) -> float:
        text_fields = [
            technique.name.lower(),
            technique.description.lower(),
            " ".join(technique.platforms).lower(),
            " ".join(technique.data_sources).lower(),
            " ".join(technique.mitigations).lower()
        ]

        full_text = " ".join(text_fields)

        keyword_matches = 0
        total_keywords = len(keywords)

        for keyword in keywords:
            if keyword.lower() in full_text:
                keyword_matches += 1

        if total_keywords == 0:
            return 0.0

        base_score = keyword_matches / total_keywords

        if any(keyword.lower() in technique.name.lower() for keyword in keywords):
            base_score *= 1.5

        return min(base_score, 1.0)
    
    def get_technique_by_id(self, technique_id: str) -> Optional[AttackTechnique]:
        techniques = self.get_all_techniques()
        for technique in techniques:
            if technique.id == technique_id:
                return technique
        return None

    def get_tactic_by_id(self, tactic_id: str) -> Optional[AttackTactic]:
        tactics = self.get_all_tactics()
        for tactic in tactics:
            if tactic.id == tactic_id:
                return tactic
        return None

    def get_techniques_by_tactic(self, tactic_id: str) -> List[AttackTechnique]:
        techniques = self.get_all_techniques()
        return [tech for tech in techniques if tactic_id in tech.tactic_ids]
