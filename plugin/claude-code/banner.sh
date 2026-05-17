#!/usr/bin/env bash
# Mantis ASCII banner — shell-side renderer.
# Honors NO_COLOR and non-TTY stderr like the Rust banner module.
# Source this file or invoke directly: `bash banner.sh`.

set -eu

print_banner() {
    if [[ -n "${MANTIS_NO_BANNER:-}" ]]; then
        return 0
    fi

    local mint='' dim='' reset=''
    if [[ -z "${NO_COLOR:-}" ]] && [[ -t 2 ]]; then
        mint=$'\033[38;2;130;240;180m'
        dim=$'\033[38;2;160;160;180m'
        reset=$'\033[0m'
    fi

    {
        printf '\n'
        printf '%s███╗   ███╗ █████╗ ███╗   ██╗████████╗██╗███████╗%s\n' "$mint" "$reset"
        printf '%s████╗ ████║██╔══██╗████╗  ██║╚══██╔══╝██║██╔════╝%s\n' "$mint" "$reset"
        printf '%s██╔████╔██║███████║██╔██╗ ██║   ██║   ██║███████╗%s\n' "$mint" "$reset"
        printf '%s██║╚██╔╝██║██╔══██║██║╚██╗██║   ██║   ██║╚════██║%s\n' "$mint" "$reset"
        printf '%s██║ ╚═╝ ██║██║  ██║██║ ╚████║   ██║   ██║███████║%s\n' "$mint" "$reset"
        printf '%s╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚══════╝%s\n' "$mint" "$reset"
        printf '\n'
        printf '    %sstalk · wait · strike · hold%s\n' "$dim" "$reset"
        printf '    ethically hack any website with the power of AI\n'
        printf '\n'
    } >&2
}

print_banner "$@"
