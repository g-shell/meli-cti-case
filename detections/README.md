# Regras de detecção — CTI-2026-0927-001

Regras e ferramentas prontas para uso, derivadas da análise do hash do case
`7a8fc48ce4df4448b91a1e6b66410cca6993ac072cb12860b9cfa6438b25ed8e`
(dropper macOS do ecossistema AMOS/MacSync distribuído via ClearFake).

| Arquivo | Tipo | Fidelidade | Uso |
|---|---|---|---|
| [`yara/macos_amos_macsync_clearfake.yar`](yara/macos_amos_macsync_clearfake.yar) | YARA (4 regras) | Alta → baixa (ver `meta.fidelity`) | Varredura de disco, EDR com suporte a YARA, retro-hunt |
| [`sigma/macos_launchagent_random_label_creation.yml`](sigma/macos_launchagent_random_label_creation.yml) | Sigma `file_event` | Alta | Criação de LaunchAgent `com.<user>.<16 letras>.plist` |
| [`sigma/macos_launchctl_load_random_label.yml`](sigma/macos_launchctl_load_random_label.yml) | Sigma `process_creation` | Alta | `launchctl load` desse plist |
| [`sigma/macos_killall_terminal_from_shell.yml`](sigma/macos_killall_terminal_from_shell.yml) | Sigma `process_creation` | Média | `killall Terminal` por shell (ocultação ClickFix) |
| [`triage/macos_triage.sh`](triage/macos_triage.sh) | Script bash (somente leitura) | — | Coleta de evidências em host macOS suspeito |

## Validação realizada

Automatizada em [`tests/test_detections.py`](../tests/test_detections.py):

- **YARA:** compila com yara-python 4.5. É testada contra amostras sintéticas
  positivas (header FAT com o identifier da assinatura, plist malicioso,
  loader ClickFix) e negativas (FAT sem identifier, plist legítimo, script benigno).
- **Sigma:** parse sem erros no pySigma. A conversão para Lucene e EQL é feita com
  `pysigma-backend-elasticsearch`. As regex são checadas com *fullmatch*,
  porque Lucene e EQL exigem casamento da string inteira.
- **Script:** `bash -n` e shellcheck (`-S warning`) sem apontamentos.

**Limitação:** o binário original não pôde ser baixado (a chave do abuse.ch usada
não permite download). Por isso as regras `MELI_MacOS_Dropper_LaunchAgent_Hunting`
e `MELI_Script_ClickFix_Loader_Hunting` são **hipóteses**, com strings não
confirmadas contra a amostra. A regra exata usa o identifier da assinatura
reportado pelo VirusTotal e o SHA-256.

## YARA

```bash
yara -r detections/yara/macos_amos_macsync_clearfake.yar ~/Library/LaunchAgents ~/Library ~/Downloads /tmp
```

`MELI_MacOS_LaunchAgent_RandomLabel_Plist` foi feita para varrer os diretórios de
LaunchAgents. As regras `*_Hunting` devem rodar primeiro fora da produção, para
medir falsos positivos.

## Sigma → Elastic Security (ECS / Elastic Defend)

Conversão gerada com `pysigma-backend-elasticsearch`, usando o mapeamento de
campos `Image → process.executable`, `CommandLine → process.command_line`,
`ParentImage → process.parent.executable` e `TargetFilename → file.path`.
Acrescente `host.os.type:"macos"` e o filtro de `event.category` do índice.

**LaunchAgent com label aleatório (Lucene)**

```text
file.path:/.*\/Library\/LaunchAgents\/com\.[A-Za-z0-9_.-]{1,64}\.[a-z]{16}\.plist/ AND (process.executable:(\/Users\/* OR \/tmp\/* OR \/private\/tmp\/* OR \/private\/var\/folders\/* OR \/Volumes\/*))
```

**launchctl load com label aleatório (EQL)**

```eql
any where (process.executable:"*/launchctl" and (process.command_line like~ ("* load *", "* bootstrap *"))) and process.command_line regex~ ".*LaunchAgents\/com\\.[A-Za-z0-9_.-]{1,64}\\.[a-z]{16}\\.plist.*"
```

**killall Terminal por shell (EQL)**

```eql
any where process.executable:"*/killall" and process.command_line:"*Terminal*" and (process.parent.executable like~ ("*/sh", "*/bash", "*/zsh"))
```

Para gerar novamente:

```powershell
python -m pip install -r requirements-dev.txt
python detections/convert_sigma.py              # Lucene e EQL
python detections/convert_sigma.py --target eql
```

## Script de triagem macOS

```bash
chmod +x macos_triage.sh
sudo ./macos_triage.sh --logs 7 > "triage_$(hostname)_$(date +%Y%m%d).txt"
echo $?   # 0 = limpo, 1 = achados, 2 = erro de uso
```

O script cobre o checklist de DFIR de um host macOS possivelmente infectado:
- LaunchAgents com label aleatório e seus conteúdos (`plutil -p`), além dos jobs ativos no launchd.
- Payload irmão `~/Library/<16 letras>`.
- Busca de hashes de IOC e Mach-O sem Team ID em diretórios graváveis.
- Históricos de shell (vetor ClickFix) e de navegador (domínios de IOC).
- Staging em `/tmp` e logs unificados (`launchctl`, `killall`, `osascript`, `dscl -authonly`).

Ele é **somente leitura**: não remove artefatos nem descarrega jobs, para
preservar as evidências. Para cobrir todos os usuários, rode com `sudo` e conceda
Full Disk Access ao Terminal. Não foi executado em macOS neste ambiente;
valide em uma VM antes de distribuir.
