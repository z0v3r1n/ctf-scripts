#!/usr/bin/env bash
# Usage: run from ~/Desktop/ctf-scripts
# Requires: ropr, gadget-finder.py

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROP_SCRIPT="/home/kali/Desktop/lifip/the-fless/gadget-finder.py"
REGS="rdx"

glibcver() { strings "$1" | grep -m1 -oP 'glibc \K[0-9.]+'; }

declare -A seen_versions

echo "[*] Scanning libc files..."

while IFS= read -r libpath; do
    basename "$libpath" | grep -qE '^libc(\.so|-[0-9])' || continue

    full="${SCRIPT_DIR}/${libpath#./}"
    [[ -f "$full" ]] || { echo "[-] Not found: $full"; continue; }

    ver=$(glibcver "$full")

    if [[ -z "$ver" ]]; then
        echo "[-] Could not determine version for: $libpath"
        continue
    fi

    if [[ -n "${seen_versions[$ver]}" ]]; then
        echo "[~] Skipping $libpath  (version $ver already covered by ${seen_versions[$ver]})"
    else
        seen_versions[$ver]="$libpath"
        echo "[+] $ver  ->  $libpath"
    fi
done < <(find . | grep -E '/(libc\.so|libc\.so\.[0-9]|libc-[0-9])' | sort)

echo ""
echo "[*] Unique versions found: ${#seen_versions[@]}"
echo "================================================"

for ver in $(echo "${!seen_versions[@]}" | tr ' ' '\n' | sort -V); do
    libpath="${seen_versions[$ver]}"
    full="${SCRIPT_DIR}/${libpath#./}"
    echo ""
    echo ">>> glibc $ver  ($libpath)"
    echo "--- Stack pivot gadgets (controlled: $REGS) ---"
    python3 "$ROP_SCRIPT" "$full" "$REGS"
    echo "------------------------------------------------"
done
