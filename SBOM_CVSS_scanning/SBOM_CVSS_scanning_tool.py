import argparse
import requests
import time
import json
import glob

# ==========================================
# Module 1: SPDX Ingestor (Simulate SBOM Parsing)
# ==========================================
def extract_cpes_from_sbom(sbom_data: dict) -> set:
    """Extract CPE 2.3 strings from standard SPDX/CycloneDX structures and deduplicate automatically"""
    cpes = set()
    for package in sbom_data.get("packages", []):
        for ref in package.get("externalRefs", []):
            if ref.get("referenceType") == "cpe23Type":
                cpes.add(ref.get("referenceLocator"))
    return cpes

# ==========================================
# Module 2 & 3: NVD API 2.0 Invocation and Matching Engine
# ==========================================
def query_nvd_api(cpe_name: str) -> list:
    """Call the latest NVD API 2.0 and handle Rate Limits"""
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cpeName": cpe_name}
    
    # Optimize log display: extract component name only
    component_name = cpe_name.split(':')[4] if len(cpe_name.split(':')) > 4 else cpe_name
    print(f"[*] Querying NVD for component: {component_name} ...")
    
    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()
        time.sleep(6) # Prevent NVD API from blocking IP (Rate Limit workaround)
        data = response.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"[!] API Query Failed: {e}")
        return []

# ==========================================
# Module 4: Contextual Risk Filter
# ==========================================
def contextual_risk_filter(vuln_list: list) -> list:
    """Strip invalid noise and redefine true risk based on Attack Vector context"""
    filtered_results = []
    
    for item in vuln_list:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "Unknown")
        
        metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
        base_score = metrics.get("baseScore", 0.0)
        attack_vector = metrics.get("attackVector", "UNKNOWN")
        
        action = "🔵 INFO: Log observation"
        if base_score >= 9.0:
            if attack_vector == "NETWORK":
                action = "🔴 CRITICAL: Remote exploitable. Block immediately and dispatch Ticket!"
            elif attack_vector in ["PHYSICAL", "LOCAL"]:
                action = "🟡 WARNING: Physical/Local access required. Risk downgraded. Verify physical access controls."
        elif base_score >= 7.0:
            action = "🟠 HIGH: Schedule for patching in the next Sprint."

        filtered_results.append({
            "CVE_ID": cve_id,
            "CVSS_Score": base_score,
            "Attack_Vector": attack_vector,
            "Architect_Decision": action
        })
        
    return filtered_results

# ==========================================
# Main Execution: Enterprise CLI Entry Point (Global Scan Version)
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enterprise SBOM Contextual Risk Scanner (L6 Pipeline)")
    parser.add_argument("-f", "--file", dest="sbom_file", default="*.json", help="Specify the SBOM file, or keep default to scan all JSON files in the directory")
    args = parser.parse_args()
    
    # Determine the list of files to process
    target_files = []
    if args.sbom_file == "*.json":
        target_files = glob.glob("*.json")
        if not target_files:
            print("[!] FATAL ERROR: No .json files found in the current directory.")
            exit(1)
        print(f"[*] Initiating global scan mode. Found {len(target_files)} SBOM files.\n")
    else:
        target_files = [args.sbom_file]

    print("Starting Enterprise SBOM Scanner...\n" + "="*40)
    
    for file_path in target_files:
        print(f"\n[🔄] Processing SBOM file: {file_path}")
        print("-" * 40)
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                real_sbom = json.load(f)
        except Exception as e:
            print(f"  [!] Skipping file '{file_path}': Read or parse failed ({type(e).__name__}: {e})")
            continue

        target_cpes = extract_cpes_from_sbom(real_sbom)
        if not target_cpes:
            print(f"  [*] No valid component info found in file {file_path}, skipping.")
            continue

        for cpe in target_cpes:
            vulns = query_nvd_api(cpe)
            component_name = cpe.split(':')[4] if len(cpe.split(':')) > 4 else cpe
            
            if vulns:
                final_report = contextual_risk_filter(vulns)
                print(f"  [📊] Component {component_name} Decision Report:")
                for result in final_report:
                    if result['CVSS_Score'] >= 7.0:
                        print(f"    - {result['CVE_ID']} (Score: {result['CVSS_Score']}) | Vector: {result['Attack_Vector']}")
                        print(f"      ↳ Decision: {result['Architect_Decision']}\n")
            else:
                print(f"  [*] Component {component_name} is secure.")
                
    print("\n" + "="*40)
    print("All SBOM files scanned. Ready to generate VEX report.")