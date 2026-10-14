#!/bin/sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LIST=${CORPUS_LIST:-$ROOT/testdata/corpus/charts.txt}
VALUES=${CORPUS_VALUES:-$ROOT/testdata/corpus/values}
OUT=${CORPUS_OUT:-$ROOT/temp/corpus}
HELM_IMAGE=${HELM_IMAGE:-alpine/helm:4.3.0}
GIT_IMAGE=${GIT_IMAGE:-alpine/git:v2.49.1}
GO_IMAGE=${GO_IMAGE:-golang:1.27}

mkdir -p "$OUT/bin" "$OUT/src" "$OUT/rendered" "$OUT/results" "$OUT/cache/go" "$OUT/cache/helm"
OUT=$(cd "$OUT" && pwd)
UIDGID="$(id -u):$(id -g)"

echo "building ai-guard with $GO_IMAGE"
docker run --rm -u "$UIDGID" -e HOME=/tmp -e GOCACHE=/work/out/cache/go/build -e GOPATH=/work/out/cache/go/path \
  -e CGO_ENABLED=0 -v "$ROOT:/work/src:ro" -v "$OUT:/work/out" -w /work/src \
  "$GO_IMAGE" go build -o /work/out/bin/ai-guard .

helm() {
  docker run --rm -u "$UIDGID" -e HOME=/tmp -e HELM_CACHE_HOME=/work/out/cache/helm \
    -e HELM_CONFIG_HOME=/work/out/cache/helm/config -e HELM_DATA_HOME=/work/out/cache/helm/data \
    -v "$OUT:/work/out" -v "$VALUES:/work/values:ro" "$HELM_IMAGE" "$@"
}

git_fetch() {
  dir=$1 url=$2 sha=$3
  [ -d "$OUT/src/$dir/.git" ] && return 0
  mkdir -p "$OUT/src/$dir"
  docker run --rm --entrypoint sh -u "$UIDGID" -e HOME=/tmp -v "$OUT/src/$dir:/repo" -w /repo "$GIT_IMAGE" \
    -c "git init -q . && git remote add origin '$url' && git fetch -q --depth 1 origin '$sha' && git checkout -q FETCH_HEAD"
}

ok=0
failed=0
: > "$OUT/summary.tsv"
while IFS='|' read -r id type source chart version values; do
  case "$id" in ''|'#'*) continue ;; esac
  rdir="$OUT/rendered/$id"
  rm -rf "$rdir"
  mkdir -p "$rdir"
  vals=""
  [ -n "$values" ] && vals="-f /work/values/$values"
  status=ok
  case "$type" in
    repo) helm template rel "$chart" --repo "$source" --version "$version" $vals >"$rdir/all.yaml" 2>"$rdir/error.txt" || status=fail ;;
    oci) helm template rel "$source" --version "$version" $vals >"$rdir/all.yaml" 2>"$rdir/error.txt" || status=fail ;;
    git)
      if git_fetch "$id" "$source" "$version" 2>"$rdir/error.txt"; then
        helm template rel "/work/out/src/$id/$chart" --dependency-update $vals >"$rdir/all.yaml" 2>>"$rdir/error.txt" || status=fail
      else
        status=fail
      fi ;;
    *) echo "unknown type $type for $id" >&2; status=fail ;;
  esac
  if [ "$status" = fail ]; then
    echo "render failed: $id: $(head -c 200 "$rdir/error.txt")"
    failed=$((failed + 1))
    continue
  fi
  rm -f "$rdir/error.txt"
  objs=$(grep -c '^kind:' "$rdir/all.yaml" || true)
  workloads=$(grep -cE '^kind: (Deployment|StatefulSet|DaemonSet|Job|CronJob|Pod)$' "$rdir/all.yaml" || true)
  rc=0
  "$OUT/bin/ai-guard" scan --path "$rdir" >"$OUT/results/$id.txt" 2>&1 || rc=$?
  [ "$rc" -le 1 ] || { echo "scan error: $id (exit $rc)"; failed=$((failed + 1)); continue; }
  "$OUT/bin/ai-guard" scan --path "$rdir" --json >"$OUT/results/$id.json" 2>/dev/null || true
  findings=$(grep -c '"id"' "$OUT/results/$id.json" || true)
  printf '%s\t%s\t%s\t%s\n' "$id" "$objs" "$workloads" "$findings" >> "$OUT/summary.tsv"
  ok=$((ok + 1))
done < "$LIST"

echo
printf '%-26s %8s %10s %9s\n' set objects workloads findings
while IFS='	' read -r id objs workloads findings; do
  printf '%-26s %8s %10s %9s\n' "$id" "$objs" "$workloads" "$findings"
done < "$OUT/summary.tsv"
echo
echo "rendered and scanned: $ok, failed: $failed"
echo "results: $OUT/results"
[ "$failed" -eq 0 ]
