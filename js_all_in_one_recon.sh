#!/usr/bin/env bash
# js_all_in_one_recon.sh - Ultra-optimized for speed
# Usage: ./js_all_in_one_recon.sh -f <js_list_file> [-d <target_domain>] [-s <status_codes>] [-c <concurrency>] [-o <output_format>] [-p] [-C]
# Example: ./js_all_in_one_recon.sh -f js_files.txt -d example.com -s 200,404 -c 20 -o json -p -C

set -euo pipefail

# Defaults
INFILE=""
TARGET_DOMAIN=""
STATUS_CODES=""
CONCURRENCY=$(nproc)  # Dynamic concurrency
OUTPUT_FORMAT="txt"
PROGRESS=false
CACHE=false
PROFILE=false
OUTDIR="/dev/shm/js_recon_out_$(date +%Y%m%d_%H%M%S)"
USE_PARALLEL=false
[[ -x "$(command -v parallel)" ]] && USE_PARALLEL=true

# Parse flags
while getopts ":f:d:s:c:o:pC" opt; do
  case $opt in
    f) INFILE="$OPTARG" ;;
    d) TARGET_DOMAIN="$OPTARG" ;;
    s) STATUS_CODES="$OPTARG" ;;
    c) CONCURRENCY="$OPTARG" ;;
    o) OUTPUT_FORMAT="$OPTARG" ;;
    p) PROGRESS=true ;;
    C) CACHE=true ;;
    \?) echo "Invalid option: -$OPTARG" >&2; exit 1 ;;
    :) echo "Option -$OPTARG requires an argument." >&2; exit 1 ;;
  esac
done

# Validate
[[ -z "$INFILE" || ! -f "$INFILE" ]] && { echo "Usage: $0 -f <js_list_file> [-d <target_domain>] [-s <status_codes>] [-c <concurrency>] [-o txt|json] [-p] [-C]"; exit 1; }
[[ "$OUTPUT_FORMAT" != "txt" && "$OUTPUT_FORMAT" != "json" ]] && { echo "Invalid output format"; exit 1; }
mkdir -p "$OUTDIR"/{raw,pretty,extracted,probes,report}
trap 'rm -rf "$OUTDIR"' EXIT

log_error() { echo "[ERROR] $(date -u +%T) $*" >> "$OUTDIR/errors.log"; }

# Read and dedupe URLs
mapfile -t JS_URLS < <(awk '/^\s*$/ || /#/{next} {print}' "$INFILE" | sort -u)
[[ ${#JS_URLS[@]} -eq 0 ]] && { log_error "No valid URLs"; exit 1; }

# Download
download_js() {
  local url="$1" i="$2"
  local outfn="$OUTDIR/raw/$(echo -n "$url" | md5sum | cut -d' ' -f1).js"
  $CACHE && [[ -s "$outfn" ]] && return
  curl -fsSL --max-time 30 --retry 2 "$url" -o "$outfn" || log_error "Download failed: $url"
  $PROGRESS && echo "[*] $(date -u +%T) Downloaded $i/${#JS_URLS[@]}" >&2
}

echo "[*] $(date -u +%T) Downloading ${#JS_URLS[@]} files..."
$PROFILE && time_cmd="time" || time_cmd=""
if $USE_PARALLEL; then
  export -f download_js OUTDIR CACHE PROGRESS
  $time_cmd parallel --line-buffer -j "$CONCURRENCY" download_js '{1}' {#} ::: "${JS_URLS[@]}"
else
  i=0
  for url in "${JS_URLS[@]}"; do
    i=$((i+1))
    download_js "$url" "$i" &
    (( i % CONCURRENCY == 0 )) && wait
  done
  wait
fi

# Prettify
prettify_js() {
  local f="$1" base="$(basename "$f")" pretty="$OUTDIR/pretty/$base.js"
  $CACHE && [[ -s "$pretty" ]] && return
  if command -v js-beautify >/dev/null 2>&1; then
    js-beautify "$f" > "$pretty" 2>/dev/null || cp "$f" "$pretty"
  elif command -v prettier >/dev/null 2>&1; then
    prettier --parser babel "$f" > "$pretty" 2>/dev/null || cp "$f" "$pretty"
  else
    tr -s '[:space:]' ' ' < "$f" | sed 's/^[[:space:]]*//g' > "$pretty" || cp "$f" "$pretty"
  fi
}

echo "[*] $(date -u +%T) Prettifying..."
if $USE_PARALLEL; then
  export -f prettify_js OUTDIR CACHE
  $time_cmd parallel -j "$CONCURRENCY" prettify_js ::: "$OUTDIR"/raw/*
else
  for f in "$OUTDIR"/raw/*; do
    prettify_js "$f" &
    (( $(jobs -p | wc -l) >= CONCURRENCY )) && wait -n
  done
  wait
fi

# Extractions
ABS_URL_RE='https?://[A-Za-z0-9.-]+/[A-Za-z0-9./?&=%_-]*'
REL_EP_RE='/[A-Za-z0-9._/?=&-]{3,100}'
SECRETS_RE='AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z-_]{35}|hooks\.slack\.com/services/[A-Za-z0-9/_-]+'
AUTH_RE='localStorage|sessionStorage|cookie|Authorization|access_token|refresh_token|setItem|getItem|Bearer'
DANGEROUS_RE='document\.write|innerHTML|insertAdjacentHTML|eval\(|new Function|setTimeout\(|Function\(|outerHTML'

echo "[*] $(date -u +%T) Extracting..."
$time_cmd rg -l 'https?://|AKIA|localStorage|document\.write' "$OUTDIR/pretty" | xargs rg -Pho --no-line-number "$ABS_URL_RE|$REL_EP_RE|$SECRETS_RE|$AUTH_RE|$DANGEROUS_RE" | \
  awk -F'|' '{if ($0 ~ /https?:\/\//) print $0 > "'"$OUTDIR/extracted/absolute_urls.txt"'"; 
              else if ($0 ~ /^\/[A-Za-z0-9]/) print $0 > "'"$OUTDIR/extracted/relative_endpoints.txt"'"; 
              else if ($0 ~ /AKIA|AIza|hooks\.slack/) print $0 > "'"$OUTDIR/extracted/suspected_secrets.txt"'"; 
              else if ($0 ~ /localStorage|cookie/) print $0 > "'"$OUTDIR/extracted/auth_related_strings.txt"'"; 
              else print $0 > "'"$OUTDIR/extracted/dangerous_sinks_with_ctx.txt"'"}' &
wait
for f in "$OUTDIR/extracted/"*.txt; do sort -u -o "$f" "$f"; done

# Host detection and URL mapping
: > "$OUTDIR/extracted/urls_to_probe.txt"
if [[ -s "$OUTDIR/extracted/absolute_urls.txt" ]]; then
  tee >(cut -d/ -f3 | sed 's/:.*//' | sort -u > "$OUTDIR/extracted/hosts.txt") \
      < "$OUTDIR/extracted/absolute_urls.txt" >> "$OUTDIR/extracted/urls_to_probe.txt"
elif [[ -n "$TARGET_DOMAIN" ]]; then
  echo "$TARGET_DOMAIN" > "$OUTDIR/extracted/hosts.txt"
fi

if [[ -s "$OUTDIR/extracted/relative_endpoints.txt" && -s "$OUTDIR/extracted/hosts.txt" ]]; then
  echo "[*] $(date -u +%T) Mapping endpoints..."
  if [[ -n "$TARGET_DOMAIN" ]]; then
    awk -v d="$TARGET_DOMAIN" '{print "https://" d ($0 ~ /^\// ? $0 : "/" $0)}' "$OUTDIR/extracted/relative_endpoints.txt" >> "$OUTDIR/extracted/urls_to_probe.txt"
  else
    while read -r host; do
      awk -v h="$host" '{print "https://" h ($0 ~ /^\// ? $0 : "/" $0)}' "$OUTDIR/extracted/relative_endpoints.txt" >> "$OUTDIR/extracted/urls_to_probe.txt"
    done < "$OUTDIR/extracted/hosts.txt"
  fi
fi
sort -u -o "$OUTDIR/extracted/urls_to_probe.txt" "$OUTDIR/extracted/urls_to_probe.txt"

# Probe
if command -v httpx >/dev/null 2>&1 && [[ -s "$OUTDIR/extracted/urls_to_probe.txt" ]]; then
  echo "[*] $(date -u +%T) Probing..."
  httpx_cmd="httpx -silent -status -title -ip -content-type -threads $CONCURRENCY -follow-redirects -timeout 10 -o $OUTDIR/probes/httpx_results.txt"
  [[ -n "$STATUS_CODES" ]] && httpx_cmd="$httpx_cmd -sc $STATUS_CODES"
  $time_cmd timeout 300s cat "$OUTDIR/extracted/urls_to_probe.txt" | $httpx_cmd || log_error "httpx failed"
fi

# Query params and cookies
[[ -s "$OUTDIR/probes/httpx_results.txt" ]] && awk '/\?/{print $1}' "$OUTDIR/probes/httpx_results.txt" | sort -u > "$OUTDIR/extracted/urls_with_query.txt"
if command -v httpx >/dev/null 2>&1 && [[ -s "$OUTDIR/extracted/hosts.txt" ]]; then
  echo "[*] $(date -u +%T) Checking cookies..."
  while read -r host; do
    echo "---- $host ----" >> "$OUTDIR/probes/cookie_flags_summary.txt"
    echo "https://$host" | httpx -silent -H 'User-Agent: recon-bot' -headers | rg -i 'set-cookie' -n || echo "No Set-Cookie" >> "$OUTDIR/probes/cookie_flags_summary.txt"
  done < "$OUTDIR/extracted/hosts.txt"
fi

# Report
echo "[*] $(date -u +%T) Generating report..."
REPORT="$OUTDIR/report/triage_summary.$OUTPUT_FORMAT"
if [[ "$OUTPUT_FORMAT" == "json" && -x "$(command -v jq)" ]]; then
  jq -n --arg infile "$INFILE" --arg target "$TARGET_DOMAIN" --arg status "$STATUS_CODES" \
    --arg js "$(ls -1 "$OUTDIR/raw" | wc -l)" \
    --arg abs "$(wc -l < "$OUTDIR/extracted/absolute_urls.txt" || echo 0)" \
    --arg rel "$(wc -l < "$OUTDIR/extracted/relative_endpoints.txt" || echo 0)" \
    --arg secrets "$(wc -l < "$OUTDIR/extracted/suspected_secrets.txt" || echo 0)" \
    --arg auth "$(wc -l < "$OUTDIR/extracted/auth_related_strings.txt" || echo 0)" \
    --arg sinks "$(wc -l < "$OUTDIR/extracted/dangerous_sinks_with_ctx.txt" || echo 0)" \
    --arg probe "$(wc -l < "$OUTDIR/extracted/urls_to_probe.txt" || echo 0)" \
    --arg httpx "$(wc -l < "$OUTDIR/probes/httpx_results.txt" || echo 0)" \
    '{
      generated: (now | strftime("%Y-%m-%d %H:%M:%SZ")),
      input_file: $infile, target_domain: $target, status_codes: $status,
      counts: {js_files: $js|tonumber, absolute_urls: $abs|tonumber, relative_endpoints: $rel|tonumber, 
               suspected_secrets: $secrets|tonumber, auth_strings: $auth|tonumber, dangerous_sinks: $sinks|tonumber,
               urls_to_probe: $probe|tonumber, probed_urls: $httpx|tonumber},
      recommendations: ["Review secrets/sinks", "Test XSS safely", "Disclose responsibly"]
    }' > "$REPORT"
else
  {
    echo "JS Recon Triage Report"
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Input: $INFILE"
    [[ -n "$TARGET_DOMAIN" ]] && echo "Target: $TARGET_DOMAIN"
    [[ -n "$STATUS_CODES" ]] && echo "Status filter: $STATUS_CODES"
    echo "Counts:"
    echo " - JS files: $(ls -1 "$OUTDIR/raw" | wc -l)"
    echo " - Abs URLs: $(wc -l < "$OUTDIR/extracted/absolute_urls.txt" || echo 0)"
    echo " - Rel EPs: $(wc -l < "$OUTDIR/extracted/relative_endpoints.txt" || echo 0)"
    echo " - Secrets: $(wc -l < "$OUTDIR/extracted/suspected_secrets.txt" || echo 0)"
    echo " - Auth: $(wc -l < "$OUTDIR/extracted/auth_related_strings.txt" || echo 0)"
    echo " - Sinks: $(wc -l < "$OUTDIR/extracted/dangerous_sinks_with_ctx.txt" || echo 0)"
    echo " - Probes: $(wc -l < "$OUTDIR/extracted/urls_to_probe.txt" || echo 0)"
    echo " - Httpx: $(wc -l < "$OUTDIR/probes/httpx_results.txt" || echo 0)"
    echo "Top Abs URLs:"; head -15 "$OUTDIR/extracted/absolute_urls.txt" || true
    echo "Top Secrets:"; head -15 "$OUTDIR/extracted/suspected_secrets.txt" || true
    echo "Top Sinks:"; head -20 "$OUTDIR/extracted/dangerous_sinks_with_ctx.txt" || true
    echo "Recommendations: Review secrets/sinks, test XSS safely, disclose responsibly"
  } > "$REPORT"
fi

# CSV
[[ -s "$OUTDIR/probes/httpx_results.txt" ]] && awk 'BEGIN{OFS=","}{gsub(/,/, " "); print $1,$2,$3,$4,$5}' "$OUTDIR/probes/httpx_results.txt" > "$OUTDIR/probes/httpx_results.csv"

echo "[*] Done. Report: $REPORT"
