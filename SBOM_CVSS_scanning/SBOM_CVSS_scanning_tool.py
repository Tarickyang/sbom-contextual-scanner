#SBOM-CVSS scanning tool - Author: Tarick Yang
import argparse
import requests
import time
import json
import glob
import os
from datetime import datetime

# ==========================================
# Module 0: Environment Context Loader (SoC Security / Enclave)
# ==========================================
def load_environment_context():
    """Load hardware and execution environment parameters (Simulating data retrieved from BMC or SPDM)"""
    context_file = 'env_context.json'
    
    # Auto-generate a default configuration with Enclave enabled if the context file is missing
    if not os.path.exists(context_file):
        default_context = {
            "asset_id": "L6-AI-SERVER-001",
            "hardware_trust": {
                "spdm_attestation": "SUCCESS",
                "secure_boot_fused": True
            },
            "execution_environment": {
                "silicon_enclave_active": True, # SoC Security parameter
                "is_air_gapped": False
            }
        }
        with open(context_file, 'w') as f:
            json.dump(default_context, f, indent=4)
        print(f"[*] Created default hardware context file: {context_file}")
    
    with open(context_file, 'r') as f:
        return json.load(f)

# ==========================================
# Module 1: SPDX Ingestor
# ==========================================
def extract_cpes_from_sbom(sbom_data: dict) -> set:
    """Extract CPE 2.3 strings from standard SPDX/CycloneDX structures"""
    cpes = set()
    for package in sbom_data.get("packages", []):
        for ref in package.get("externalRefs", []):
            if ref.get("referenceType") == "cpe23Type":
                cpes.add(ref.get("referenceLocator"))
    return cpes

# ==========================================
# Module 2: Local Cache(Prevent being KTO) NVD API 2.0 Invocation
# ==========================================
CACHE_FILE = "nvd_cache.json"

def load_nvd_cache() -> dict:
    """Load the local NVD API cache to avoid redundant network calls."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_nvd_cache(cache_data: dict):
    """Save NVD API responses to the local cache."""
    with open(CACHE_FILE, "w") as f:
        json.dump(cache_data, f, indent=4)

def query_nvd_api(cpe_name: str, cache_data: dict) -> list:
    """Call NVD API 2.0 with Local Caching to bypass rate limits on known CPEs."""
    component_name = cpe_name.split(':')[4] if len(cpe_name.split(':')) > 4 else cpe_name
    
    # Check Local Cache First
    if cpe_name in cache_data:
        print(f"  [⚡] CACHE HIT: Retrieved {component_name} from local storage instantly.")
        return cache_data[cpe_name]

    # Cache Miss -> Query API
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cpeName": cpe_name}
    
    print(f"  [*] CACHE MISS: Querying NVD API for {component_name} ...")
    
    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()
        time.sleep(6) # NIST API Rate Limit cooldown (only for new queries)
        data = response.json()
        vulns = data.get("vulnerabilities", [])
        
        # Update Cache
        cache_data[cpe_name] = vulns
        save_nvd_cache(cache_data)
        
        return vulns
    except Exception as e:
        print(f"  [!] API Query Failed: {e}")
        return []

# ==========================================
# Module 3: Multi-Dimensional Contextual Risk Filter (CVSS 4.0 Ready)
# ==========================================
def contextual_risk_filter(vuln_list: list, env: dict) -> list:
    """Evaluate true risk using FULL CVSS 4.0 parameters + SoC Enclave status"""
    filtered_results = []
    
    hw_trust = env.get("hardware_trust", {})
    exec_env = env.get("execution_environment", {})
    spdm_ok = hw_trust.get("spdm_attestation") == "SUCCESS"
    enclave_on = exec_env.get("silicon_enclave_active", False)
    secure_boot_on = hw_trust.get("secure_boot_fused", False)

    for item in vuln_list:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "Unknown")
        
        metrics = cve.get("metrics", {})
        
        # default values
        cvss_version = "UNKNOWN"
        base_score = 0.0
        vector_string = "UNKNOWN"
        av = ac = at = pr = ui = "X"
        e = au = "X" # Threat & Supplemental
        
        # prioritize parsing CVSS 4.0
        if "cvssMetricV40" in metrics:
            cvss_data = metrics["cvssMetricV40"][0].get("cvssData", {})
            cvss_version = "4.0"
            base_score = cvss_data.get("baseScore", 0.0)
            vector_string = cvss_data.get("vectorString", "UNKNOWN")
            
            # Base Metrics
            av = cvss_data.get("attackVector", "X")
            ac = cvss_data.get("attackComplexity", "X")
            at = cvss_data.get("attackRequirements", "X") # Applicable to CVSS 4.0 only
            pr = cvss_data.get("privilegesRequired", "X")
            ui = cvss_data.get("userInteraction", "X")
            
            # Threat & Supplemental Metrics (if NVD provides)
            e = cvss_data.get("exploitMaturity", "NOT_DEFINED")
            au = cvss_data.get("automatable", "NOT_DEFINED")
            
        # downgrade compatible CVSS 3.1
        elif "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_version = "3.1"
            base_score = cvss_data.get("baseScore", 0.0)
            vector_string = cvss_data.get("vectorString", "UNKNOWN")
            av = cvss_data.get("attackVector", "X")
            ac = cvss_data.get("attackComplexity", "X")
            pr = cvss_data.get("privilegesRequired", "X")
            ui = cvss_data.get("userInteraction", "X")
            at = "N/A" # 3.1 doesn't have AT
        
        vex_status = "affected"
        action = "🔴 CRITICAL: Requires immediate patching." if base_score >= 9.0 else "🟠 HIGH: Schedule for next Sprint."
        justification = "Standard CVSS Evaluation."

        # [CVSS 4.0  Matrix]

        # Rule 1: Physical attack (AV:P) + Secure Boot
        if av == "PHYSICAL" and secure_boot_on and spdm_ok:
            vex_status = "not_affected"
            action = "🔵 INFO: Physical risk downgraded."
            justification = "Hardware Root of Trust & Secure Boot prevents physical tampering."

        # Rule 2: SoC Enclave + Attack Requirements (AT) / Complexity (AC)
        elif enclave_on:
            # if the vulnerability requires special conditions (AT:P) or high complexity (AC:H), and has Enclave protection
            if at == "PRESENT" or ac == "HIGH":
                vex_status = "not_affected"
                action = "🟢 MITIGATED: Enclave Shield Active."
                justification = f"Enclave isolates execution. Exploit requires specific conditions (AT:{at[:1]}/AC:{ac[:1]}) which are blocked by SoC."
            
            # if the vulnerability is not automatable (AU:N) and requires high privileges (PR:H)
            elif au == "NO" and pr == "HIGH":
                vex_status = "not_affected"
                action = "🟢 MITIGATED: Enclave + Non-wormable."
                justification = "Requires High PR and is not automatable. Enclave boundary effectively neutralizes risk."

        # Rule 3: Exploit Maturity (E) 威
        if vex_status == "affected" and e == "UNREPORTED":
            action = "🟡 WARNING: Theoretical risk only."
            justification = "Exploit Maturity is UNREPORTED. Downgraded priority."

        filtered_results.append({
            "CVE_ID": cve_id,
            "Version": cvss_version,
            "CVSS_Score": base_score,
            "Vector": vector_string, #  Vector String ( VC, VI, VA, SC, SI, SA )
            "VEX_Status": vex_status,
            "Architect_Decision": action,
            "Justification": justification
        })
        
    return filtered_results

# ==========================================
# Module 4-1: VEX JSON & HTML Dashboard Exporter - for PowerBI view
# ==========================================
def export_vex_and_html(all_results: list, env: dict):
    if not all_results:
        return

    # 1. Export VEX JSON
    vex_doc = {
        "metadata": {"author": "Tarick - Enterprise VulnOps", "timestamp": datetime.now().isoformat()},
        "statements": []
    }
    for r in all_results:
        vex_doc["statements"].append({
            "vulnerability_id": r['CVE_ID'],
            "status": r['VEX_Status'],
            "justification": r['Justification'] if r['VEX_Status'] == "not_affected" else "none",
            "impact_statement": r['Architect_Decision'],
            "cvss_vector": r['Vector'] # for PowerBI view
        })
    with open("trinity_vex_report.json", "w") as f:
        json.dump(vex_doc, f, indent=4)
    
    # 2. Export PowerBI HTML (vector string for PowerBI view)
    total = len(all_results)
    filtered = sum(1 for r in all_results if r['VEX_Status'] == "not_affected")
    actionable = total - filtered
    
    html = f"""
    <!DOCTYPE html><html><head><title>L6 Pipeline Security Dashboard</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #121212; color: #e0e0e0; margin: 40px; }}
        .header {{ background: #004455; padding: 20px; border-radius: 8px; border-left: 5px solid #00c3ff; }}
        .kpi-row {{ display: flex; gap: 20px; margin: 20px 0; }}
        .kpi {{ background: #1e1e1e; padding: 20px; border-radius: 8px; flex: 1; text-align: center; border: 1px solid #333; }}
        .num {{ font-size: 2.5em; font-weight: bold; color: #00c3ff; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e1e1e; font-size: 13px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; word-break: break-all; }}
        th {{ background: #2a2a2a; color: #aaa; }}
        .safe {{ color: #5cb85c; font-weight: bold; }}
        .vuln {{ color: #d9534f; font-weight: bold; }}
        .vector {{ font-family: monospace; color: #888; font-size: 11px; }}
    </style></head><body>
        <div class="header">
            <h2>🛡️ Hardware-Aware VulnOps Dashboard (CVSS 4.0 Native)</h2>
            <p>Asset: {env['asset_id']} | SPDM: {env['hardware_trust']['spdm_attestation']} | SoC Enclave: {'ACTIVE' if env['execution_environment']['silicon_enclave_active'] else 'INACTIVE'}</p>
        </div>
        <div class="kpi-row">
            <div class="kpi"><h3>Total CVEs Processed</h3><div class="num">{total}</div></div>
            <div class="kpi"><h3>Noise Filtered</h3><div class="num" style="color: #5cb85c;">{filtered}</div></div>
            <div class="kpi"><h3>Actionable Tickets</h3><div class="num" style="color: #ffaa00;">{actionable}</div></div>
        </div>
        <table>
            <tr><th width="12%">CVE ID</th><th width="8%">Score (Ver)</th><th width="35%">CVSS Vector String</th><th width="10%">VEX Status</th><th width="35%">Justification</th></tr>
            {"".join([f"<tr><td>{r['CVE_ID']}</td><td>{r['CVSS_Score']} ({r['Version']})</td><td class='vector'>{r['Vector']}</td><td class='{'safe' if r['VEX_Status']=='not_affected' else 'vuln'}'>{r['VEX_Status'].upper()}</td><td>{r['Justification']}</td></tr>" for r in all_results])}
        </table>
    </body></html>
    """
    with open("trinity_dashboard.html", "w", encoding='utf-8') as f:
        f.write(html)

# ==========================================
# Module 4-2: VEX JSON & HTML Dashboard Exporter
# ==========================================
def export_vex_and_html(all_results: list, env: dict):
    if not all_results:
        return

    # 1. Export VEX JSON
    vex_doc = {
        "metadata": {"author": "Tarick - Enterprise VulnOps", "timestamp": datetime.now().isoformat()},
        "statements": []
    }
    for r in all_results:
        vex_doc["statements"].append({
            "vulnerability_id": r['CVE_ID'],
            "status": r['VEX_Status'],
            "justification": r['Justification'] if r['VEX_Status'] == "not_affected" else "none",
            "impact_statement": r['Architect_Decision']
        })
    with open("trinity_vex_report.json", "w") as f:
        json.dump(vex_doc, f, indent=4)
    
    # 2. Export PowerBI HTML
    total = len(all_results)
    filtered = sum(1 for r in all_results if r['VEX_Status'] == "not_affected")
    actionable = total - filtered
    
    html = f"""
    <!DOCTYPE html><html><head><title>L6 Pipeline Security Dashboard</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #121212; color: #e0e0e0; margin: 40px; }}
        .header {{ background: #004455; padding: 20px; border-radius: 8px; border-left: 5px solid #00c3ff; }}
        .kpi-row {{ display: flex; gap: 20px; margin: 20px 0; }}
        .kpi {{ background: #1e1e1e; padding: 20px; border-radius: 8px; flex: 1; text-align: center; border: 1px solid #333; }}
        .num {{ font-size: 2.5em; font-weight: bold; color: #00c3ff; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e1e1e; font-size: 14px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #2a2a2a; color: #aaa; }}
        .safe {{ color: #5cb85c; font-weight: bold; }}
        .vuln {{ color: #d9534f; font-weight: bold; }}
    </style></head><body>
        <div class="header">
            <h2>🛡️ Hardware-Aware VulnOps Dashboard</h2>
            <p>Asset: {env['asset_id']} | SPDM: {env['hardware_trust']['spdm_attestation']} | SoC Enclave: {'ACTIVE' if env['execution_environment']['silicon_enclave_active'] else 'INACTIVE'}</p>
        </div>
        <div class="kpi-row">
            <div class="kpi"><h3>Total CVEs Processed</h3><div class="num">{total}</div></div>
            <div class="kpi"><h3>Noise Filtered (Enclave)</h3><div class="num" style="color: #5cb85c;">{filtered}</div></div>
            <div class="kpi"><h3>Actionable Tickets</h3><div class="num" style="color: #ffaa00;">{actionable}</div></div>
        </div>
        <table>
            <tr><th>CVE ID</th><th>Score</th><th>Metrics (AV/AC/PR/UI/S)</th><th>VEX Status</th><th>Justification</th></tr>
           {"".join([f"<tr><td>{r['CVE_ID']}</td><td>{r['CVSS_Score']} ({r['Version']})</td><td class='vector'>{r['Vector']}</td><td class='{'safe' if r['VEX_Status']=='not_affected' else 'vuln'}'>{r['VEX_Status'].upper()}</td><td>{r['Justification']}</td></tr>" for r in all_results])}
        </table>
    </body></html>
    """
    with open("trinity_dashboard.html", "w", encoding='utf-8') as f:
        f.write(html)
    print("\n[*] Output Generated: 'trinity_vex_report.json' and 'trinity_dashboard.html'")

# ==========================================
# Main Execution
# ==========================================
if __name__ == "__main__":
    # Force working directory to script location]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    print(f"[SYSTEM] Working Directory locked to: {script_dir}\n")

    parser = argparse.ArgumentParser(description="Enterprise SBOM Contextual Risk Scanner (L6 Pipeline)")
    parser.add_argument("-f", "--file", dest="sbom_file", default="*.json", help="Specify the SBOM file")
    args = parser.parse_args()
    
    # find SBOM file
    target_files = glob.glob("*.json") if args.sbom_file == "*.json" else [args.sbom_file]
    
    # ignore generated json
    target_files = [f for f in target_files if f not in ["env_context.json", "trinity_vex_report.json", "nvd_cache.json"]]
    
    if not target_files:
        print("[!] FATAL ERROR: No valid SBOM .json files found.")
        print(f"    -> Engine searched in: {script_dir}")
        print("    -> Action: Please ensure your SBOM file (e.g., test_sbom.json) is placed in this exact folder.")
        exit(1)
    print("="*50)
    print("Trinity Contextual Scanner activating...")
    env_context = load_environment_context()
    nvd_cache = load_nvd_cache() 
    print("="*50)
    
    global_results = []

    for file_path in target_files:
        print(f"\n[*] Processing SBOM: {file_path}")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                real_sbom = json.load(f)
        except Exception as e:
            print(f"  [!] Skip: {e}")
            continue

        target_cpes = extract_cpes_from_sbom(real_sbom)
        for cpe in target_cpes:
            vulns = query_nvd_api(cpe, nvd_cache) # 傳入 Cache 字典
            if vulns:
                component_report = contextual_risk_filter(vulns, env_context)
                global_results.extend(component_report)
                
                for r in component_report:
                    if r['VEX_Status'] == 'affected':
                        print(f"    -> 🚨 {r['CVE_ID']} ({r['Vector']}) | {r['Architect_Decision']}")
                    else:
                        print(f"    -> 🛡️ {r['CVE_ID']} Filtered by SoC Enclave")

    export_vex_and_html(global_results, env_context)
    print("\n[*] Scan Complete.")
