#!/usr/bin/env bash
set -euo pipefail

report_path="${1:-coverage.txt}"
target_percent="${2:-90}"
row_limit="${3:-50}"

if [[ ! -f "${report_path}" ]]; then
    echo "coverage report not found: ${report_path}" >&2
    exit 1
fi

if ! [[ "${target_percent}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "target percentage must be numeric: ${target_percent}" >&2
    exit 1
fi

if ! [[ "${row_limit}" =~ ^[1-9][0-9]*$ ]]; then
    echo "row limit must be a positive integer: ${row_limit}" >&2
    exit 1
fi

echo "Current report: $(awk '/^[0-9.]+% coverage, [0-9]+\/[0-9]+ lines covered/ { line=$0 } END { print line }' "${report_path}")"
echo "Files needing the most new covered lines to reach ${target_percent}%:"
printf '%-9s %-9s %-9s %-9s %s\n' "NEEDED" "COVERED" "TOTAL" "CURRENT" "FILE"

awk -v target="${target_percent}" '
    /^\|\| .*: [0-9]+\/[0-9]+$/ {
        ratio = $NF
        split(ratio, counts, "/")
        covered = counts[1] + 0
        total = counts[2] + 0
        wanted = int((total * target / 100) + 0.999999)
        needed = wanted - covered
        if (needed <= 0) {
            next
        }
        path = $0
        sub(/^\|\| /, "", path)
        sub(/: [0-9]+\/[0-9]+$/, "", path)
        current = total == 0 ? 100 : (covered * 100 / total)
        printf "%09d\t%d\t%d\t%.2f%%\t%s\n", needed, covered, total, current, path
    }
' "${report_path}" \
    | sort -t $'\t' -k1,1nr -k5,5 \
    | awk -F '\t' -v limit="${row_limit}" '
        NR <= limit {
            needed = $1 + 0
            printf "%-9d %-9d %-9d %-9s %s\n", needed, $2, $3, $4, $5
        }
    '

awk -v target="${target_percent}" '
    /^[0-9.]+% coverage, [0-9]+\/[0-9]+ lines covered/ {
        split($3, counts, "/")
        covered = counts[1] + 0
        total = counts[2] + 0
    }
    END {
        wanted = int((total * target / 100) + 0.999999)
        gap = wanted - covered
        if (gap < 0) {
            gap = 0
        }
        printf "\nWorkspace target: %.2f%% (%d/%d); remaining newly covered lines: %d\n", target, wanted, total, gap
    }
' "${report_path}"
