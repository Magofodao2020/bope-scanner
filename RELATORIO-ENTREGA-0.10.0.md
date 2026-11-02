# B.O.P.E Scanner 0.10.0 — relatório de entrega

Baseado no código-fonte da 0.9.0 recebido (`bope-scanner-0.9.0-src.zip`). O código 0.9.0 foi
extraído sem alterações em `src-tree/` e registrado num commit próprio; todas as mudanças da 0.10.0
estão nos commits seguintes da branch `claude/loving-tesla-4f7hmj`, auditáveis por `git diff`.

## Arquivos entregues

| Arquivo | Conteúdo |
|---|---|
| `bope-scanner-0.10.0-src.zip` | Código-fonte completo (GPL-3.0-or-later) |
| `bope-scanner-0.10.0-windows-x64.zip` | `bope-scanner.exe`, `bope-scanner-cli.exe`, `WebView2Loader.dll`, `validate-windows.ps1`, `SHA256SUMS.txt`, `LEIA-ME.txt`, `NOTICE`, licença |
| `src-tree/` | O mesmo código-fonte, versionado |

## O que foi implementado

| Item pedido | Estado | Onde |
|---|---|---|
| 3.1 SRUM | **Implementado.** Leitor ESE próprio, limitado, sem `unsafe` (páginas 4–32 KiB, catálogo, colunas fixas/variáveis/tagged, compressão 7-bit e XPRESS). Lê `SRUDB.dat` do arquivo vivo e, se bloqueado, da shadow copy **já existente** mais nova. CPU registrada → classe `resource_usage` (conta como execução na correlação). SIDs nunca lidos | ADR 0124; `bope_parsers::{ese,srum}`, coletor `srum` |
| 3.2 `$MFT` / metadados NTFS | **Implementado (metadados).** Leitura bruta somente leitura de `\\.\C:` (admin, verificação avançada), registros em uso e **liberados** com nome do catálogo, caminho reconstruído, horários SI/FN, `si_created_before_fn`. Conteúdo de arquivos **não** é recuperado (decisão documentada) | ADR 0125; `bope_parsers::ntfs`, coletor `mft` |
| 3.3 ShellBags e OpenSavePidlMRU | **Implementado.** Parser de shell items (raízes, volumes, entradas com extensão `0xBEEF0004`, rede); só caminhos com nome do catálogo ou do Roblox (verificação avançada) | ADR 0126; `bope_parsers::shell_items`, coletor `shellbags` |
| 3.4 Assinaturas WMI permanentes | **Implementado.** COM/WMI só com `ExecQuery` em `ROOT\subscription` e `ROOT\default`; filtros, consumidores, vínculos; programa com SHA-256 e assinatura; texto de script nunca guardado | ADR 0127; `bope_host_windows::wmi`, coletor `wmi_subscription` |
| 4. RAR e 7z | **Implementado.** RAR 4/5 e 7z pelo índice, sem extrair; cabeçalho 7z LZMA/LZMA2 descomprimido com teto de 16 MiB (`lzma-rs` 0.3.0, MIT, `forbid(unsafe_code)`); cabeçalhos criptografados informados | ADR 0128; `bope_parsers::archive_names`, `roblox_files` |
| 5. PDF | **Implementado nativamente**, sem dependência (PDF 1.4, fontes padrão, WinAnsi, determinístico), com o SHA-256 do JSON equivalente; CLI e interface | ADR 0129; `bope_core::pdf` |
| 6. Tradução das regras | **Concluída**: descrição, retenção e falsos positivos em pt-BR para as 71 regras herdadas que só tinham título; IDs, campos e termos técnicos preservados; tailandês intacto | `rules/i18n/pt-BR.yaml` |
| 7. Testes em Windows 10/11 | **Não executados** (sem Windows disponível). Entregues procedimento e script automatizável | `docs/bope/validacao-windows.md`, `scripts/validate-windows.ps1` |
| 8. Integração | Cada fonte: coletor, parser, estados (lida / não verificada com motivo / fora desta verificação / erro), catálogo, `roblox_trace`, deduplicação por família (registro MFT em uso = mesma família da listagem de pastas), 9 regras novas com fixtures positivas/negativas, interface, relatórios, consentimento (CLI/desktop/PRIVACY) | |
| 10. Guia manual | Seção 7A em `docs/bope/guia-pc-check-roblox.md` | |

## Testes executados (resultados reais desta sessão)

| Verificação | Resultado |
|---|---|
| `cargo test --workspace --exclude bope-desktop` | **1 081 aprovados**, 0 falhas, 1 ignorado (o desktop exige webkit2gtk no Linux; compila para Windows) |
| `pnpm test` (interface) | **75 aprovados** |
| `pnpm typecheck`, `pnpm lint` | ok |
| `cargo clippy --all-targets -D warnings` | ok no Linux e no alvo `x86_64-pc-windows-msvc` |
| `cargo fmt --check` | ok |
| `cargo xtask check-rules` | 152 regras, 328 fixtures, 3 idiomas ok |
| `cargo xtask check-baseline` | 152 regras quietas em 4 baselines; 107 confrontadas, 45 justificadas em `unconfronted.csv` (3 novas: as duas regras WMI e a de arquivo com cabeçalho criptografado — sem baseline medida) |
| `rules-reference --check`, `check-locales`, `check-unicode`, `check-versions` | ok (versão 0.10.0 em todo lugar) |
| `reuse lint` | 1 089/1 089 arquivos conformes |
| Compilação Windows (`x86_64-pc-windows-gnu`, MinGW-w64) | `bope-scanner.exe` e `bope-scanner-cli.exe` gerados (PE32+ x86-64) |
| `cargo deny check` (incluindo a nova dependência `lzma-rs`) | advisories, bans, licenses, sources ok |

Testes novos cobrem: leitor ESE (páginas 4 e 32 KiB, várias páginas, limites, lixo), SRUM, NTFS
(fixups, registros, data runs, registro rasgado), shell items, RAR4/RAR5/7z (com e sem LZMA, cabeçalho
criptografado, teto de tamanho), PDF (tabela xref, escapes, quebra de linha, determinismo), cada
coletor (encontrado, vazio, não admin, acesso negado, ausente, corrompido), correlação com as novas
fontes, ponta a ponta com a fixture `roblox-tool-history` estendida (SRUM, MFT, ShellBags, OpenSave e
WMI), exportação PDF redigida no modo SS, e interface (formato PDF, rótulos das fontes).

## Limitações e bloqueios — leia antes de usar

1. **Nada foi executado num Windows real.** Os executáveis foram compilados, não executados (sem
   Windows nem Wine no ambiente). SRUM, MFT, ShellBags e o leitor ESE foram testados só com dados
   **sintéticos** gerados pelos próprios construtores do projeto; o código COM/WMI e a leitura bruta de
   volume compilam para Windows mas nunca rodaram. Use `docs/bope/validacao-windows.md` antes de
   confiar nesses resultados numa screenshare.
2. **SRUM e Amcache dependem de shadow copy existente** e de admin; sem elas ficam NÃO VERIFICADOS. Logs
   de transação do ESE não são aplicados; valores em long-value tree, multi-valores e XPRESS9/10 não
   são lidos (informado como parcial).
3. **MFT:** só a unidade do sistema; listas de atributos/registros de extensão não são resolvidos;
   nenhum conteúdo é recuperado.
4. **ShellBags:** horários de chave do Registro não são lidos (a interface de Registro do host não
   expõe last-write time); os horários mostrados são os FAT do item.
5. **PDF:** caracteres fora do Windows-1252 (tailandês) saem como `?`.
6. **RAR 4 com nome Unicode:** só a parte ASCII do nome é lida.
7. Binários não assinados digitalmente (SmartScreen pode avisar), como na 0.9.0.

Nenhuma conclusão do programa diz "limpo" ou "culpado"; uma referência histórica isolada continua
sendo INFO/SUSPEITO, nunca veredito.
