#!/bin/bash
#
# CTI-2026-0927-001 — Triagem de host macOS: dropper AMOS/MacSync via ClearFake
# Hash de referência: 7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e
#
# SOMENTE LEITURA: não remove, não descarrega LaunchAgents e não altera o sistema.
# Arquivos temporários (cópias de histórico do navegador) ficam em um diretório
# mktemp removido ao final.
#
# Uso:
#   sudo ./macos_triage.sh              # todos os usuários
#   sudo ./macos_triage.sh --logs 7     # inclui logs unificados dos últimos 7 dias (lento)
#   ./macos_triage.sh > triage_$(hostname)_$(date +%Y%m%d).txt
#
# Saída: relatório em stdout. Código de saída 0 = nada encontrado,
#        1 = achados que exigem análise, 2 = erro de uso.
#
# Compatível com o bash 3.2 do macOS.

set -u

LOG_DAYS=0

while [ $# -gt 0 ]; do
    case "$1" in
        --logs)
            LOG_DAYS="${2:-7}"
            case "$LOG_DAYS" in
                ''|*[!0-9]*) echo "uso: $0 [--logs DIAS]" >&2; exit 2 ;;
            esac
            shift 2
            ;;
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *)
            echo "uso: $0 [--logs DIAS]" >&2
            exit 2
            ;;
    esac
done

if [ "$(uname -s)" != "Darwin" ]; then
    echo "Este script é destinado a macOS." >&2
    exit 2
fi

FINDINGS=0
WORKDIR="$(mktemp -d -t cti_triage)"
trap 'rm -rf "$WORKDIR"' EXIT

# IOCs da análise do hash do case
IOC_HASHES="7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e
b34241006b130412756e834250f2f73da11f895183040618e030b50b5951da9a
e6e72f978548b80f2e72e9dcf1d7f8c4b7b05a5e045c876651b91405714415c1
541ae24e7dcbfb4738574dc103428eff9c1d4aa247a7b362ff89c61b93d85006"
IOC_DOMAINS_RE='wi-7-e\.ru|x-3-ri\.ru|relocatejacket\.com'
IOC_IP='89.169.54.153'
RANDOM_LABEL_RE='^com\.[A-Za-z0-9_.-]{1,64}\.[a-z]{16}\.plist$'
RANDOM_FILE_RE='^[a-z]{16}$'

section() {
    printf '\n==== %s ====\n' "$1"
}

finding() {
    FINDINGS=$((FINDINGS + 1))
    printf '[ACHADO] %s\n' "$1"
}

info() {
    printf '  %s\n' "$1"
}

is_ioc_hash() {
    printf '%s\n' "$IOC_HASHES" | grep -qx "$1"
}

sha256_of() {
    shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
}

user_homes() {
    for home in /Users/* /private/var/root; do
        [ -d "$home/Library" ] || continue
        case "$(basename "$home")" in
            Shared|Guest) continue ;;
        esac
        printf '%s\n' "$home"
    done
}

describe_file() {
    local file="$1"
    local digest
    digest="$(sha256_of "$file")"
    info "arquivo : $file"
    info "sha256  : ${digest:-?}"
    info "tamanho : $(stat -f '%z bytes' "$file" 2>/dev/null)"
    info "criado  : $(stat -f '%SB' "$file" 2>/dev/null)"
    info "modific.: $(stat -f '%Sm' "$file" 2>/dev/null)"
    if [ -n "$digest" ] && is_ioc_hash "$digest"; then
        finding "hash corresponde a IOC conhecido: $file"
    fi
}

printf 'Triagem CTI-2026-0927-001\nHost: %s\nData: %s\nmacOS: %s\nExecutado como: %s\n' \
    "$(hostname)" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    "$(sw_vers -productVersion 2>/dev/null)" "$(id -un)"

if [ "$(id -u)" -ne 0 ]; then
    echo "AVISO: sem sudo, apenas o usuário atual será inspecionado integralmente."
fi

# 1. LaunchAgents / LaunchDaemons com label aleatório
section "1. LaunchAgents/LaunchDaemons com padrão com.<usuário>.<16 letras>.plist"

PLIST_DIRS="/Library/LaunchAgents /Library/LaunchDaemons"
for home in $(user_homes); do
    PLIST_DIRS="$PLIST_DIRS $home/Library/LaunchAgents"
done

for dir in $PLIST_DIRS; do
    [ -d "$dir" ] || continue
    for plist in "$dir"/*.plist; do
        [ -e "$plist" ] || continue
        name="$(basename "$plist")"
        if printf '%s' "$name" | grep -Eq "$RANDOM_LABEL_RE"; then
            finding "plist com label aleatório: $plist"
            describe_file "$plist"
            info "conteúdo:"
            plutil -p "$plist" 2>/dev/null | sed 's/^/    /'
        fi
    done
done

# 2. Agentes carregados
section "2. Jobs carregados no launchd com label aleatório"

loaded="$(launchctl list 2>/dev/null | awk '{print $3}' | grep -E '^com\.[A-Za-z0-9_.-]{1,64}\.[a-z]{16}$')"
if [ -n "$loaded" ]; then
    printf '%s\n' "$loaded" | while read -r label; do
        finding "job ativo: $label"
    done
    FINDINGS=$((FINDINGS + $(printf '%s\n' "$loaded" | wc -l)))
else
    info "nenhum (contexto do usuário atual; repetir por usuário se necessário)"
fi

# 3. Script irmão ~/Library/<16 letras>
section "3. Arquivos ~/Library/<16 letras minúsculas> (payload de segundo estágio)"

for home in $(user_homes); do
    for file in "$home"/Library/*; do
        [ -f "$file" ] || continue
        if basename "$file" | grep -Eq "$RANDOM_FILE_RE"; then
            finding "arquivo com nome aleatório em $home/Library"
            describe_file "$file"
            info "tipo    : $(file -b "$file" 2>/dev/null)"
            info "início  :"
            head -c 400 "$file" 2>/dev/null | strings | head -n 10 | sed 's/^/    /'
        fi
    done
done

# 4. Busca por hashes conhecidos e binários ad-hoc em diretórios graváveis
section "4. Hashes de IOC e Mach-O sem Team ID em diretórios graváveis"

for home in $(user_homes); do
    SEARCH_DIRS="$home/Desktop $home/Downloads $home/Library"
    for dir in $SEARCH_DIRS; do
        [ -d "$dir" ] || continue
        find "$dir" -maxdepth 2 -type f -size -2048k \( -name 'apps*' -o -perm -u+x \) 2>/dev/null
    done
done > "$WORKDIR/candidates.txt"

for dir in /tmp /private/tmp /Users/Shared; do
    [ -d "$dir" ] && find "$dir" -maxdepth 2 -type f -size -2048k 2>/dev/null
done >> "$WORKDIR/candidates.txt"

while IFS= read -r candidate; do
    [ -f "$candidate" ] || continue
    digest="$(sha256_of "$candidate")"
    if [ -n "$digest" ] && is_ioc_hash "$digest"; then
        finding "arquivo com hash de IOC: $candidate"
        describe_file "$candidate"
        continue
    fi
    if file -b "$candidate" 2>/dev/null | grep -q 'Mach-O'; then
        team="$(codesign -dv "$candidate" 2>&1 | awk -F= '/^TeamIdentifier/{print $2}')"
        if [ -z "$team" ] || [ "$team" = "not set" ]; then
            info "Mach-O sem Team ID (revisar): $candidate  sha256=$digest"
        fi
    fi
done < "$WORKDIR/candidates.txt"

# 5. Histórico de shell: vetor ClickFix
section "5. Histórico de shell (curl | sh, base64, osascript, IOCs)"

for home in $(user_homes); do
    for history in "$home/.zsh_history" "$home/.bash_history" "$home"/.zsh_sessions/*.history; do
        [ -f "$history" ] || continue
        hits="$(grep -aEn "curl[^|]*\|[[:space:]]*(ba|z)?sh|base64[[:space:]]+(-d|--decode|-D)|osascript|$IOC_DOMAINS_RE|$IOC_IP" "$history" 2>/dev/null | tail -n 20)"
        if [ -n "$hits" ]; then
            finding "comandos suspeitos em $history"
            printf '%s\n' "$hits" | sed 's/^/    /'
        fi
    done
done

# 6. Histórico do navegador (cópia em diretório temporário)
section "6. Histórico de navegador com domínios de IOC"

if command -v sqlite3 >/dev/null 2>&1; then
    for home in $(user_homes); do
        for db in \
            "$home/Library/Application Support/Google/Chrome/Default/History" \
            "$home/Library/Application Support/BraveSoftware/Brave-Browser/Default/History" \
            "$home/Library/Safari/History.db"; do
            [ -f "$db" ] || continue
            copy="$WORKDIR/history_$$.db"
            cp "$db" "$copy" 2>/dev/null || { info "sem acesso (Full Disk Access?): $db"; continue; }
            case "$db" in
                *Safari*) query="SELECT url FROM history_items;" ;;
                *) query="SELECT url FROM urls;" ;;
            esac
            hits="$(sqlite3 "$copy" "$query" 2>/dev/null | grep -Ei "$IOC_DOMAINS_RE" | head -n 20)"
            rm -f "$copy"
            if [ -n "$hits" ]; then
                finding "domínio de IOC no histórico: $db"
                printf '%s\n' "$hits" | sed 's/^/    /'
            fi
        done
    done
else
    info "sqlite3 indisponível; etapa ignorada"
fi

# 7. Staging em /tmp
section "7. Possível staging de exfiltração em /tmp"

find /tmp /private/tmp -maxdepth 2 \( -name '*.zip' -o -iname '*keychain*' -o -iname '*login data*' -o -iname '*cookies*' \) \
    -mtime -30 2>/dev/null | while read -r staged; do
    info "revisar: $staged"
done

# 8. Logs unificados (opcional)
section "8. Logs unificados"

if [ "$LOG_DAYS" -gt 0 ]; then
    log show --style syslog --last "${LOG_DAYS}d" --predicate \
        '(process == "launchctl" AND eventMessage CONTAINS "LaunchAgents") OR (process == "killall") OR (process == "osascript") OR (process == "dscl" AND eventMessage CONTAINS "authonly")' \
        2>/dev/null | grep -Ei 'LaunchAgents/com\.|killall|display dialog|authonly' | tail -n 50 > "$WORKDIR/logs.txt"
    if [ -s "$WORKDIR/logs.txt" ]; then
        finding "eventos relevantes nos logs unificados (${LOG_DAYS}d)"
        sed 's/^/    /' "$WORKDIR/logs.txt"
    else
        info "nenhum evento relevante nos últimos ${LOG_DAYS} dias"
    fi
else
    info "ignorado (use --logs DIAS)"
fi

section "Resumo"
if [ "$FINDINGS" -gt 0 ]; then
    printf 'ACHADOS: %d — tratar como possível comprometimento.\n' "$FINDINGS"
    printf 'Próximos passos: isolar o host, preservar evidências e revogar sessões/rotacionar credenciais do usuário (relatório, seção 7).\n'
    exit 1
fi

printf 'Nenhum indicador encontrado. Ausência de achados não descarta variantes; correlacionar com EDR/SIEM.\n'
exit 0
