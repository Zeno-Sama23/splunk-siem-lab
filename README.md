# Splunk SIEM Lab — SPL Detection Rules

Lab Splunk Enterprise avec ingestion de **vrais logs d'attaques** depuis une VM Metasploitable2. Ecriture de 4 regles de detection SPL mappees MITRE ATT&CK, dashboard de monitoring et analyse de logs Linux authentiques.

---

## Architecture

```
Windows 11 Host
├── Splunk Enterprise (localhost:8000)
│   ├── Index: lab
│   └── Sourcetype: linux_secure
│
└── VirtualBox Host-Only Network
    └── Metasploitable2 (192.168.56.104)
        └── /var/log/auth.log  ← source des vrais logs
```

**Logs reels** : Le fichier `auth.log` provient directement de Metasploitable2 apres simulation d'attaques SSH brute force reelles depuis le host Windows.

---

## MITRE ATT&CK Coverage

| Regle | Technique | ID | Severite | Resultat |
|-------|-----------|-----|----------|---------|
| SSH Brute Force | Brute Force: Password Spraying | T1110.001 | High | 55 tentatives detectees |
| Login apres echecs | Valid Accounts | T1078 | High | 2 succes apres 28 echecs |
| Enumeration comptes | Account Discovery | T1087 | Medium | 9 comptes enumeres |
| Session root | Abuse Elevation Control | T1548 | High | 4 sessions root |

---

## Regles SPL

### 1. SSH Brute Force Detection (T1110.001)

```spl
index=lab sourcetype=linux_secure ("Invalid user" OR "Failed password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 5
| sort -count
```

**Resultat reel :** 55 tentatives depuis 192.168.56.1

---

### 2. Login Reussi apres Echecs (T1078)

```spl
index=lab sourcetype=linux_secure ("Failed password" OR "Invalid user" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "(?<status>Failed password|Invalid user|Accepted password)"
| stats count(eval(status="Accepted password")) as successes,
        count(eval(status!="Accepted password")) as failures by src_ip
| where successes > 0 AND failures > 3
```

**Resultat reel :** 2 connexions reussies apres 28 echecs — compte compromis

---

### 3. Enumeration de Comptes (T1087)

```spl
index=lab sourcetype=linux_secure "Invalid user"
| rex "Invalid user (?<username>\w+) from"
| stats count by username
| sort -count
```

**Resultat reel :** admin, administrator, guest, oracle, test, user, postgres, ftp, root (5 tentatives chacun)

---

### 4. Session Root Ouverte (T1548)

```spl
index=lab sourcetype=linux_secure "session opened for user root"
| rex "(?<month>\w+)\s+(?<day>\d+)\s+(?<time>\S+) (?<host>\S+) (?<process>\S+): .*session opened for user (?<user>\w+)"
| table _time, host, process, user
```

**Resultat reel :** 4 sessions root detectees sur metasploitable

---

## Dashboard

Dashboard **Metasploitable2 Security Monitoring** avec 3 panneaux :
- Brute Force par IP (graphique a barres)
- Comptes enumeres (graphique a barres)
- Timeline des evenements SSH (graphique en courbes)

---

## Fichiers

```
splunk-siem-lab/
├── README.md
├── spl-rules/
│   ├── brute-force-detection.spl       ← T1110.001
│   ├── login-after-failures.spl        ← T1078
│   ├── account-enumeration.spl         ← T1087
│   └── root-session-detection.spl      ← T1548
├── sample-logs/
│   └── metasploitable2-auth.log        ← vrais logs Linux
└── dashboard/
    └── (captures screenshots)
```

---

## Outils

| Outil | Role |
|-------|------|
| Splunk Enterprise | SIEM - ingestion et analyse |
| Metasploitable2 | Source de logs d'attaques reels |
| VirtualBox | Isolation de la VM cible |

---

## Competences demonstrees

- Ingestion de logs Linux (linux_secure sourcetype)
- Ecriture de regles SPL avec extraction de champs (rex)
- Detection de patterns d'attaques reels
- Mapping MITRE ATT&CK
- Creation de dashboards de monitoring
- Competences multi-SIEM : KQL (Sentinel) + SPL (Splunk)
