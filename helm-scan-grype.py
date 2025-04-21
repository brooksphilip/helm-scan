#!/usr/bin/env python3
import subprocess
import sys
import json
import csv
from collections import defaultdict

# Ensure tabulate is installed
try:
    from tabulate import tabulate
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "tabulate"])
    from tabulate import tabulate

def render_helm_chart(chart_path, release_name="scan-release", namespace="default", values_file=None):
    cmd = ["helm", "template", release_name, chart_path, "--namespace", namespace]
    if values_file:
        cmd += ["-f", values_file]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return proc.stdout

def extract_images(yaml_str):
    import yaml
    images = set()
    for doc in yaml.safe_load_all(yaml_str):
        if not isinstance(doc, dict):
            continue
        # Look for pod specs
        spec = doc.get("spec", {})
        # Drill into template.spec if present
        spec = spec.get("template", {}).get("spec", spec)
        for cname in ("containers", "initContainers"):
            for c in spec.get(cname, []):
                img = c.get("image")
                if img:
                    images.add(img)
    return sorted(images)

def scan_image_with_grype(image):
    cmd = ["grype", image, "-o", "json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(proc.stdout)
        return data.get("matches", [])
    except subprocess.CalledProcessError as e:
        print(f"[!] Grype scan failed for {image}:", file=sys.stderr)
        print(e.stderr or e, file=sys.stderr)
        return []

def summarize(matches):
    cnt = defaultdict(int)
    for m in matches:
        sev = m.get("vulnerability", {}).get("severity", "").capitalize()
        if sev in ("Critical", "High", "Medium", "Low"):
            cnt[sev] += 1
    return cnt

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Scan all images in a Helm chart with Grype and summarize results."
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

    total = defaultdict(int)
    per_image = []

    for img in images:
        print(f"🔍 Scanning: {img}")
        matches = scan_image_with_grype(img)
        counts = summarize(matches)
        per_image.append({
            "Image":    img,
            "Critical": counts.get("Critical", 0),
            "High":     counts.get("High",     0),
            "Medium":   counts.get("Medium",   0),
            "Low":      counts.get("Low",      0),
        })
        for sev in ("Critical","High","Medium","Low"):
            total[sev] += counts.get(sev, 0)

    # Print totals
    summary = [[
        total["Critical"], total["High"],
        total["Medium"],   total["Low"],
    ]]
    print("\n🎯 Total Vulnerability Summary:")
    print(tabulate(summary,
                   headers=["Critical", "High", "Medium", "Low"],
                   tablefmt="grid"))

    # Write CSV
    csv_file = "grype-per-image-report.csv"
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Image","Critical","High","Medium","Low"])
        writer.writeheader()
        writer.writerows(per_image)

    print(f"\n✅ Detailed per-image report written to: {csv_file}")

if __name__ == "__main__":
    main()
