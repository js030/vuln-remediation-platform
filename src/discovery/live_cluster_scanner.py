import subprocess
import json
import yaml
from typing import List, Dict

def scan_live_deployments() -> List[Dict]:
    """Scannt tatsächlich laufende Deployments im Cluster."""
    result = subprocess.run(
        ["kubectl", "get", "deployments", "-A", "-o", "json"],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        print(f"[ERROR] kubectl deployments failed: {result.stderr}")
        return []
    
    deployments = json.loads(result.stdout)
    workloads = []
    
    for item in deployments.get("items", []):
        namespace = item["metadata"]["namespace"]
        name = item["metadata"]["name"]
        containers = item["spec"]["template"]["spec"]["containers"]
        
        for idx, container in enumerate(containers):
            image = container.get("image", "")
            workloads.append({
                "type": "Deployment",
                "namespace": namespace,
                "name": name,
                "container_name": container.get("name"),
                "container_index": idx,
                "image": image,
                "source": "live-cluster"
            })
    
    return workloads

def scan_live_statefulsets() -> List[Dict]:
    """Scannt laufende StatefulSets."""
    result = subprocess.run(
        ["kubectl", "get", "statefulsets", "-A", "-o", "json"],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        return []
    
    statefulsets = json.loads(result.stdout)
    workloads = []
    
    for item in statefulsets.get("items", []):
        namespace = item["metadata"]["namespace"]
        name = item["metadata"]["name"]
        containers = item["spec"]["template"]["spec"]["containers"]
        
        for idx, container in enumerate(containers):
            image = container.get("image", "")
            workloads.append({
                "type": "StatefulSet",
                "namespace": namespace,
                "name": name,
                "container_name": container.get("name"),
                "container_index": idx,
                "image": image,
                "source": "live-cluster"
            })
    
    return workloads

def scan_live_daemonsets() -> List[Dict]:
    """Scannt laufende DaemonSets."""
    result = subprocess.run(
        ["kubectl", "get", "daemonsets", "-A", "-o", "json"],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        return []
    
    daemonsets = json.loads(result.stdout)
    workloads = []
    
    for item in daemonsets.get("items", []):
        namespace = item["metadata"]["namespace"]
        name = item["metadata"]["name"]
        containers = item["spec"]["template"]["spec"]["containers"]
        
        for idx, container in enumerate(containers):
            image = container.get("image", "")
            workloads.append({
                "type": "DaemonSet",
                "namespace": namespace,
                "name": name,
                "container_name": container.get("name"),
                "container_index": idx,
                "image": image,
                "source": "live-cluster"
            })
    
    return workloads

def scan_all_live_workloads() -> List[Dict]:
    """Scannt alle Workload-Typen im Cluster."""
    print("[LIVE-DISCOVERY] Scanning actual cluster workloads...")
    
    deployments = scan_live_deployments()
    print(f"  Found {len(deployments)} containers in Deployments")
    
    statefulsets = scan_live_statefulsets()
    print(f"  Found {len(statefulsets)} containers in StatefulSets")
    
    daemonsets = scan_live_daemonsets()
    print(f"  Found {len(daemonsets)} containers in DaemonSets")
    
    all_workloads = deployments + statefulsets + daemonsets
    print(f"[LIVE-DISCOVERY] Total: {len(all_workloads)} containers to scan")
    
    return all_workloads

def compare_git_vs_live(git_images: List[str], live_workloads: List[Dict]) -> Dict:
    """Vergleicht Git-Manifeste mit echtem Cluster-Zustand (Drift Detection)."""
    git_set = set(git_images)
    live_set = set(w["image"] for w in live_workloads)
    
    only_in_git = git_set - live_set
    only_in_live = live_set - git_set
    
    return {
        "only_in_git": list(only_in_git),
        "only_in_live": list(only_in_live),
        "in_sync": list(git_set & live_set)
    }
