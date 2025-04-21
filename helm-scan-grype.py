#!/usr/bin/env python3
import subprocess
import sys
import json
import csv
import argparse
from collections import defaultdict

# ensure PyYAML is installed
try:
    import yaml
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "pyyaml"])
    import yaml

# ensure tabulate is installed
try:
    from tabulate import tabulate
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "tabulate"])
    from tabulate import tabulate

def humanize_bytes(size):
    """Convert bytes to human-readable string."""
    if size is None:
        return "N/A"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if size < 1024.0:
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}EB"

def get_image_size(image):
    """
    Pull the image if needed and inspect its size.
    """
    try:
        subprocess.run(
            ["docker", "pull", image],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        insp = subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{.Size}}"],
            capture_output=True,
            text=True,
            check=True
        )
        size_bytes = int(insp.stdout.strip())
        return humanize_bytes(size_bytes)
    except Exception as e:
        print(f"[!] docker inspect failed for {image}: {e}", file=sys.stderr)
        return "N/A"

def get_package_count(image):
    """
    Use Syft to count packages in the image. Returns int or 'N/A'.
    """
    try:
        proc = subprocess.run(
            ["syft", image, "-o", "json"],
            capture_output=True,
            text=True,
            check=True
        )
        data = json.loads(proc.stdout)
        return len(data.get("artifacts", []))
    except Exception as e:
        print(f"[!] syft error for {image}: {e}", file=sys.stderr)
        return "N/A"

def render_helm_chart(chart, release, namespace, repo, values_file, sets):
    """
    Run `helm template` and return the rendered YAML (stderr suppressed).
    """
    cmd = [
        "helm", "template", release, chart,
        "--namespace", namespace,
        "--include-crds",
    ]
    if repo:
        cmd += ["--repo", repo]
    if values_file:
        cmd += ["-f", values_file]
    for s in sets or []:
        cmd += ["--set", s]

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=True
    )
    return proc.stdout

def extract_containers(yaml_str):
    """
    Return list of (container_name, image) tuples.
    """
    containers = []
    for doc in yaml.safe_load_all(yaml_str):
        if not isinstance(doc, dict):
            continue
        spec = doc.get("spec", {}).get("template", {}).get("spec", {})
        for cname in ("containers", "initContainers"):
            for c in spec.get(cname, []):
                img = c.get("image")
                name = c.get("name")
                if name and img:
                    containers.append((name, img))
    return containers

def scan_with_grype(image):
    """
    Scan an image with Grype and return its matches list.
    """
    try:
        out = subprocess.run(
            ["grype", image, "-o", "json"],
            capture_output=True, text=True, check=True
        ).stdout
        return json.loads(out).get("matches", [])
    except subprocess.CalledProcessError as e:
        print(f"[!] grype scan failed for {image}: {e}", file=sys.stderr)
        return []

def summarize(matches):
    """
    Count vulnerabilities by severity.
    """
    cnt = defaultdict(int)
    for m in matches:
        sev = (m.get("vulnerability", {}).get("severity") or "").capitalize()
        if sev in ("Critical", "High", "Medium", "Low"):
            cnt[sev] += 1
    return cnt

def main():
    parser = argparse.ArgumentParser(
        description="Scan all containers in a Helm chart with Grype, showing size & package count."
    )
    parser.add_argument("chart", help="Chart name or path (e.g. argo/argo-cd or ./charts/my-app)")
    parser.add_argument("--repo", help="Chart repo URL (for remote charts)")
    parser.add_argument("-n", "--namespace", default="default", help="Kubernetes namespace")
    parser.add_argument("-r", "--release", default="scan-release", help="Helm release name")
    parser.add_argument("-f", "--values", help="values.yaml file")
    parser.add_argument(
        "--set", dest="sets", action="append", default=[],
        metavar="K=V", help="Helm-style --set pairs (can repeat)"
    )
    args = parser.parse_args()

    print(f"⏳ Rendering `{args.chart}` …")
    manifests = render_helm_chart(
        args.chart, args.release, args.namespace,
        args.repo, args.values, args.sets
    )

    containers = extract_containers(manifests)
    if not containers:
        print("[!] No containers found.", file=sys.stderr)
        sys.exit(1)

    total = defaultdict(int)
    report = []

    for cname, img in containers:
        size = get_image_size(img)
        pkg_count = get_package_count(img)
        print(f"🔍 Scanning {cname}: {img} (size={size}, pkgs={pkg_count})")
        matches = scan_with_grype(img)
        counts = summarize(matches)

        row = {
            "Container": cname,
            "Image": img,
            "Size": size,
            "Packages": pkg_count,
            "Critical": counts.get("Critical", 0),
            "High": counts.get("High", 0),
            "Medium": counts.get("Medium", 0),
            "Low": counts.get("Low", 0),
        }
        report.append(row)

        for sev in ("Critical", "High", "Medium", "Low"):
            total[sev] += row[sev]

    # Print cumulative summary
    print("\n🎯 Total Vulnerabilities:")
    print(tabulate(
        [[ total[s] for s in ("Critical","High","Medium","Low") ]],
        headers=["Critical","High","Medium","Low"],
        tablefmt="grid"
    ))

    # Write CSV with extra columns
    csv_file = "grype-per-container-report.csv"
    fieldnames = ["Container","Image","Size","Packages","Critical","High","Medium","Low"]
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report)

    print(f"\n✅ Detailed per-container report written to: {csv_file}")

if __name__ == "__main__":
    main()
