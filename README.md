**Traffic Analyzer en Java avec Pcap4J** :

# READ.md – Rapport d’Analyse et de Design

## 📌 Titre du Projet

**Traffic Analyzer** – Outil d’analyse de trafic réseau en Java utilisant la bibliothèque Pcap4J.


## 👨‍💻 Membres du Projet

* **Nom :** \[YAGOU Yassir]



## 🎯 Objectif du Projet

Le but de ce projet est de développer un outil en Java capable de capturer, analyser, classifier et visualiser les paquets réseau. L'application extrait des statistiques détaillées sur les IPs, ports et conversations réseau, facilitant l’analyse de comportements réseau, la détection d’anomalies ou le diagnostic réseau.


## 🔧 Technologies Utilisées

| Composant            | Technologie            |
| -------------------- | ---------------------- |
| Langage              | Java 17                |
| Bibliothèque capture | Pcap4J                 |
| Logging              | Log4j                  |
| Format sortie        | CSV, Console           |
| Outils de parsing    | Expressions régulières |
| IDE                  | IntelliJ / Eclipse     |

## 🏗️ Architecture du Projet

com.alok.trafficanalyzer
- **PacketCapture.java**  
  Handles live packet capture from network interfaces using Pcap4J.  
  Supports saving captured traffic into `.pcap` files for offline analysis.

- **PacketClassifier.java**  
  Parses packets, extracts metadata (IP, ports, protocols), and generates statistics.  
  Provides classification logic for TCP, UDP, ICMP, etc.

- **IPStatistics.java**  
  Aggregates traffic by IP addresses.  
  Useful for identifying top talkers, suspicious hosts, or bandwidth usage.

- **PortStatistics.java**  
  Tracks traffic distribution across ports.  
  Helps detect active services, port scans, or anomalies.

- **AnalyzedPacket.java**  
  Defines a structured model for packets.  
  Encapsulates source/destination IPs, ports, protocol, flags, and payload metadata.

- **PcapReader.java**  
  Reads and parses existing `.pcap` files.  
  Enables offline traffic analysis and replay.

- **TrafficAnalyzerApp.java**  
  Main entry point of the application.  
  Provides CLI/interactive menu to launch capture, classification, and reporting.


## ⚙️ Fonctionnalités Implémentées

### ✔ Capture et enregistrement de trafic

* Capture de paquets en temps réel depuis une interface réseau.
* Sauvegarde facultative au format `.pcap`.

### ✔ Extraction des données pertinentes

* Adresse IP source/destination
* Numéros de port
* Protocole (TCP, UDP, ICMP)
* MAC source/destination
* Flags TCP, TTL, etc.

### ✔ Classification

* Comptage des paquets par IP
* Analyse des ports les plus actifs
* Partenaires de communication d’une IP

### ✔ Filtres interactifs

* Recherche par IP
* Recherche par port
* Affichage filtré des paquets concernés


## 📊 Exemples de Statistiques Générées


=== TOP IP ADDRESSES BY TRAFFIC ===
IP Address           Type       Sent     Received   Total Bytes 
----------------------------------------------------------------------
192.168.100.91       Balanced   27       52         73409       
173.194.16.233       Sender     49       23         72783

=== TOP PORTS BY TRAFFIC ===
Port     Service      Classification Packets    Bytes        Connections
----------------------------------------------------------------------
443      HTTPS        Moderate usage 78         73343        2

=== PROTOCOL STATISTICS ===
Protocol     Count
----------------------------------------------------------------------
TCP          79      
UDP          8


## 🧠 Design & Choix Techniques

* **Séparation claire** entre capture (temps réel), parsing (texte ou PCAP), et affichage.
* Utilisation d’expressions régulières pour une flexibilité maximale dans le parsing.
* Structure orientée objet pour faciliter l’extension (détection anomalies, conversations, etc.).
* Logging via Log4j pour diagnostiquer les erreurs de capture ou d’analyse.

---

## ✅ Test et Validation

* Tests manuels sur des interfaces actives (ex: WiFi, Ethernet).
* Analyse de fichiers `.pcap` préexistants.
* Vérification de la validité des champs extraits.
* Comparaison croisée avec Wireshark.

---

## 📈 Évolutions Possibles

* Interface graphique en JavaFX ou Web (Spring Boot + React)
* Détection de scans de ports ou d’attaques DoS
* Génération de rapports PDF / JSON
* Exportation vers une base de données pour analyse à long terme
* Intégration avec ELK Stack (Elasticsearch, Logstash, Kibana)

---

## 📦 Fichiers Importants

| Fichier                   | Rôle                                 |
| ------------------------- | ------------------------------------ |
| `PacketCapture.java`      | Capture de paquets en live           |
| `PacketClassifier.java`   | Analyse et affichage de stats        |
| `PcapReader.java`         | Lecture et parsing de `.pcap`        |
| `TrafficAnalyzerApp.java` | Menu principal pour lancer l’analyse |
| `captured_packets.pcap`   | Fichier d'exemple pour test          |
| `output.csv`              | Résultat structuré au format CSV     |

---

## 👋 Conclusion

Ce projet constitue une base solide pour un outil d’analyse réseau en Java, combinant efficacité, modularité et extensibilité. Il peut évoluer vers un véritable IDS/IPS ou être utilisé dans un contexte pédagogique pour comprendre le fonctionnement des protocoles.

---
