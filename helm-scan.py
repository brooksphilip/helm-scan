#!/usr/bin/env python3
import subprocess
import sys
import os
import json
import csv
from collections import defaultdict

# Ensure dependencies
try:
    import yaml
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "pyyaml"])
    import yaml

try:
    from tabulate import tabulate
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "tabulate"])
    from tabulate import tabulate

def render_helm_chart(chart_path, release_name="scan-release", namespace="default", values_file=None):
    """Run `helm template` and return the concatenated YAML string."""
    cmd = ["helm", "template", release_name, chart_path, "--namespace", namespace]
    if values_file:
        cmd += ["-f", values_file]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return proc.stdout

def extract_images(yaml_str):
    """Parse manifests and collect all container images."""
    images = set()
    for doc in yaml.safe_load_all(yaml_str):
        if not isinstance(doc, dict):
            continue
        # Look for pod specs under common controllers:
        template = None
        for path in (
            ("spec", "template", "spec"),  # Deployments, DaemonSets, StatefulSets, Jobs, etc.
            ("spec",),                     # CronJobs (the top-level spec has template further down)
        ):
            sub = doc
            for key in path:
                sub = sub.get(key, {})
            if "containers" in sub:
                template = sub
                break
        if not template:
            continue
        for cname in ("containers", "initContainers"):
            for c in template.get(cname, []):
                img = c.get("image")
                if img:
                    images.add(img)
    return sorted(images)

def scan_with_tool(image, tool):
    """Scan image with grype or trivy; returns list of matches."""
    if tool == "grype":
        cmd = [
            "grype",
            image,
            "-o", "json",
        ]
    else:
        cmd = [
            "trivy", "image",
            image,
            "--format", "json",
            "--skip-db-update",
            # If you need registry creds, you can add:
            # "--username", os.getenv("DOCKER_USERNAME", ""),
            # "--password", os.getenv("DOCKER_PASSWORD", ""),
        ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(proc.stdout)

        if tool == "grype":
            return data.get("matches", [])
        else:  # trivy
            vulns = []
            for result in data.get("Results", []):
                vulns.extend(result.get("Vulnerabilities", []) or [])
            return vulns

    except subprocess.CalledProcessError as e:
        print(f"[!] {tool} scan failed for {image}.", file=sys.stderr)
        print("    command was:", " ".join(cmd), file=sys.stderr)
        print("    stderr:\n", e.stderr or "<no stderr>", file=sys.stderr)
        return []

def summarize(matches):
    cnt = defaultdict(int)
    for m in matches:
        sev = m.get("vulnerability", {}).get("severity") or m.get("Severity")
        if not sev:
            continue
        sev = sev.capitalize()
        cnt[sev] += 1
    return cnt

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Scan all images in a Helm chart with Grype & Trivy, compare results."
    )
    parser.add_argument("chart", help="Path or name of the Helm chart")
    parser.add_argument("-n", "--namespace", default="default")
    parser.add_argument("-r", "--release", default="scan-release")
    parser.add_argument("-f", "--values", help="Optional values.yaml")
    args = parser.parse_args()

    print(f"⏳ Rendering Helm chart `{args.chart}` …")
    rendered = render_helm_chart(args.chart, args.release, args.namespace, args.values)

    images = extract_images(rendered)
    if not images:
        print("[!] No images found in chart.", file=sys.stderr)
        sys.exit(1)

    total = {
        "grype": defaultdict(int),
        "trivy": defaultdict(int),
    }
    table_rows = []
    csv_rows = []

    for img in images:
        print(f"\n🔍 Scanning image: {img}")
        row = {"Image": img}

        for tool in ("grype", "trivy"):
            matches = scan_with_tool(img, tool)
            counts = summarize(matches)
            for sev in ("Critical", "High", "Medium", "Low"):
                key = f"{tool}_{sev}"
                row[key] = counts.get(sev, 0)
                total[tool][sev] += counts.get(sev, 0)

        table_rows.append([
            img,
            row["grype_Critical"], row["trivy_Critical"],
            row["grype_High"],     row["trivy_High"],
            row["grype_Medium"],   row["trivy_Medium"],
            row["grype_Low"],      row["trivy_Low"],
        ])
        csv_rows.append(row)

    # Print comparison table
    headers = [
        "Image",
        "G-Crit", "T-Crit",
        "G-High", "T-High",
        "G-Med",  "T-Med",
        "G-Low",  "T-Low",
    ]
    print("\n📊 Per-image vulnerability comparison:")
    print(tabulate(table_rows, headers=headers, tablefmt="grid"))

    # Print totals
    total_table = [[
        total["grype"]["Critical"], total["trivy"]["Critical"],
        total["grype"]["High"],     total["trivy"]["High"],
        total["grype"]["Medium"],   total["trivy"]["Medium"],
        total["grype"]["Low"],      total["trivy"]["Low"],
    ]]
    print("\n🎯 Total Vulnerability Summary:")
    print(tabulate(total_table, headers=headers[1:], tablefmt="grid"))

    # Write CSV
    csv_file = "helm-scan-report.csv"
    fieldnames = ["Image"] + [f"{t}_{sev}" for t in ("grype", "trivy") for sev in ("Critical","High","Medium","Low")]
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)
    print(f"\n✅ Detailed CSV report written to: {csv_file}")

if __name__ == "__main__":
    main()
