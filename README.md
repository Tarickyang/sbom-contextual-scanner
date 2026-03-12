# Enterprise SBOM Contextual Risk Scanner 

A lightweight, pipeline-ready DevSecOps tool designed to ingest Software Bill of Materials (SBOM) and dynamically contextualize CVE risks using the NVD API 2.0.

##  The Problem
In modern Vulnerability Operations (VulnOps), security teams are overwhelmed by static CVSS scores. A CVSS 9.8 vulnerability often triggers midnight alerts, even if the component is deeply embedded in an air-gapped hardware environment requiring physical access. 

**Static scoring creates alert fatigue and wastes engineering cycles.**

## 💡 The Solution: Contextual Prioritization
This tool doesn't just match SBOM components against the NVD database; it applies an **Architectural Risk Filter**. By analyzing the Attack Vector (e.g., Network vs. Physical/Local), it dynamically downgrades theoretical risks to reflect actual environmental exposure.

### Key Features
- **Zero-Friction Ingestion**: Seamlessly parses standard SPDX/CycloneDX JSON formats.
- **Auto-Discovery**: Run without arguments to automatically batch-process all .json SBOMs in the directory.
- **Contextual Risk Engine**:
  - `🔴 CRITICAL`: Network-exploitable + High CVSS (Triggers immediate mitigation).
  - `🟡 WARNING`: High CVSS but requires PHYSICAL or LOCAL access (Downgraded risk).
- **Pipeline Ready**: Graceful degradation, fault tolerance, and comprehensive exception handling (Permissions, Rate Limits, Malformed JSON) built for CI/CD runners.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- requests library

### Installation
```bash
git clone [https://github.com/YOUR_USERNAME/sbom-contextual-scanner.git](https://github.com/YOUR_USERNAME/sbom-contextual-scanner.git)
cd sbom-contextual-scanner
pip install requests
