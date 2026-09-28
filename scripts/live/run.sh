#!/usr/bin/env bash
# Live cluster validation. Needs docker, kind, kubectl, helm, cilium CLI,
# and membrane installed. GitHub-hosted runners have these after the
# workflow install step. Sandboxes without registry access cannot run it.
set -euo pipefail
cd "$(dirname "$0")/../.."
LIVE=var/live
CLUSTER="${MEMBRANE_KIND_CLUSTER:-membrane-live}"
IMAGE_TAG="${MEMBRANE_LIVE_IMAGE:-curlimages/curl:8.11.1}"
CILIUM_VERSION="${CILIUM_VERSION:-1.17.4}"
KYVERNO_CHART_VERSION="${KYVERNO_CHART_VERSION:-3.4.1}"
rm -rf "$LIVE" && mkdir -p "$LIVE"

echo "== 1. Resolve the probe image to a digest"
docker pull -q "$IMAGE_TAG" >/dev/null
IMAGE_REF="$(docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE_TAG")"
echo "$IMAGE_REF" | tee "$LIVE/image-ref.txt"

echo "== 2. Build the live registry copy and generate its config"
python scripts/live/prepare.py --image-ref "$IMAGE_REF" --out "$LIVE/registry"
membrane gen --registry "$LIVE/registry" --out "$LIVE/generated"

echo "== 3. Create the kind cluster with Cilium"
kind create cluster --name "$CLUSTER" --config scripts/live/kind-config.yaml --wait 120s
cilium install --version "$CILIUM_VERSION"
cilium status --wait --wait-duration 5m

echo "== 4. Install Kyverno"
helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null
helm repo update >/dev/null
helm install kyverno kyverno/kyverno -n kyverno --create-namespace --version "$KYVERNO_CHART_VERSION" --wait --timeout 10m

echo "== 5. Namespaces, service accounts, generated config"
for ns in agents agents-finance agents-sandbox; do
  kubectl create namespace "$ns"
  kubectl label namespace "$ns" membrane.io/agent-namespace=true
done
kubectl create namespace membrane-system
python - <<'PY'
import subprocess
from membrane.manifest import load_registry
for m in load_registry("var/live/registry").values():
    rt = m.spec["runtime"]
    if rt["type"] == "k8s":
        subprocess.run(["kubectl", "create", "serviceaccount", rt["service_account"], "-n", rt["namespace"]], check=True)
# A second account in agents-finance for the wrong-service-account probe.
subprocess.run(["kubectl", "create", "serviceaccount", "not-the-agent", "-n", "agents-finance"], check=True)
PY
kubectl apply -f "$LIVE/generated/k8s/"

echo "== 6. Admission policies"
kubectl apply -f policy/admission/kyverno/membrane-agent-workloads.yaml -f policy/admission/kyverno/membrane-unregistered-agents.yaml
kubectl wait --for=condition=Ready clusterpolicy/membrane-agent-workloads clusterpolicy/membrane-unregistered-agents --timeout=180s

echo "== 7. Probes"
python scripts/live/probes.py --registry "$LIVE/registry" --image-ref "$IMAGE_REF" --out "$LIVE"
