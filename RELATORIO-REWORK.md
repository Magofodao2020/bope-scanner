# B.O.P.E Scanner — rework da interface, identidade visual e análise forense

Trabalho feito sobre a 0.10.0 na branch `claude/loving-tesla-4f7hmj` (PR #1). A versão continua 0.10.0.
Capturas da interface em `src-tree/docs/bope/capturas/` (dados sintéticos; veja o LEIA-ME de lá).

## Arquivos entregues

| Arquivo | Conteúdo |
|---|---|
| `bope-scanner-0.10.0-rework-windows-x64.zip` | `bope-scanner.exe`, `bope-scanner-cli.exe`, `WebView2Loader.dll`, `validate-windows.ps1`, `SHA256SUMS.txt`, `LEIA-ME.txt`, `NOTICE`, licença |
| `bope-scanner-0.10.0-rework-src.zip` | Código-fonte completo deste commit |
| `src-tree/` | O mesmo código, versionado |

SHA-256: `bope-scanner-0.10.0-rework-windows-x64.zip` 274b5be27cc4dc1b804a40065f6cf1016f9081f9800768a8e2c58b1236203f33 ·
`bope-scanner-0.10.0-rework-src.zip` c8c1e7f470907b9849a349b8b4e767e1d69544fe29909b214681322ca98494ef ·
`bope-scanner.exe` f9fa923c06d68adfc8247eabeb8e1c230b03b9bc633194c4a81703e5531f12b4 ·
`bope-scanner-cli.exe` d08e2e80484b576f59b017fd9df46a210064e76e865a7aca3ee78bb6e83db5d4.

## Análise inicial (antes de mudar)

- **Interface**: tela única de resultado (`Report.tsx`, ~450 linhas) com avaliação, contagens, linhas de
  evidência expansíveis, linha do tempo, idade dos rastros e exportação, tudo empilhado. "Sobre" era um
  overlay. Faixa vermelha "UNOFFICIAL BUILD" no topo de todas as telas. Tema "céu claro" herdado.
- **Progresso**: real (vinha de `scan_status`), mas o módulo "agora" era *adivinhado* pela ordem da lista da
  interface — o backend só avisava depois de cada coletor.
- **Horários**: o Rust guarda tudo em RFC 3339 UTC (`Fields::time`); a interface mostrava a string ISO
  crua, sem fuso local, sem tipo do horário. Os relatórios diziam "todos os horários em UTC".
- **Lixeira**: lida só dentro de `roblox_files`, e só itens cujo nome bate com o catálogo (`scope: recycled`,
  com `deleted_at`). Não havia horário da pasta nem das entradas `$I`/`$R`.
- **Serviços**: nada consultava o estado atual. `os_image` lia o valor `Start` no Registro de alguns
  serviços; nenhum coletor lia o histórico do Service Control Manager.

## O que foi feito

| Pedido | Estado | Onde |
|---|---|---|
| Identidade visual a partir do logo | Feito. Tokens de cor do distintivo (preto, vermelho do anel, dourado, branco), sem gradiente/brilho/emoji; ícones SVG próprios; logo na barra lateral; ícones do app (`.ico`, `.png`, `.icns`) gerados do logo | `apps/desktop/src/styles.css`, `src/assets/bope-logo.png`, `src/ui/Icon.tsx`, `src-tauri/icons/` |
| Remover "UNOFFICIAL BUILD" da interface | Faixa do topo removida. **A indicação continua** em Configurações e sobre, nos fatos da Visão geral e nos relatórios exportados, porque o NOTICE §7(c) da licença exige que o programa a mostre. Créditos e licenças agora num cartão próprio | `views/About.tsx`, `views/pages/OverviewPage.tsx`, ADR 0132 |
| Navegação | Barra lateral: Visão geral, Scanner, Evidências, Serviços do Windows, Lixeira, Linha do tempo, Relatórios, Configurações e sobre. Páginas de resultado ficam desabilitadas até existir relatório (nenhuma página vazia) | `App.tsx`, `views/pages/*` |
| Fluxo único com progresso real | O backend agora informa o coletor **em execução** (`Progress::next`, `Status.current`) e se o cancelamento foi pedido. A tela mostra módulo atual, lidos / não verificados / só na avançada / pendentes, total e tempo decorrido; a barra é a fração de módulos concluídos (sem estimativa de tempo) | `crates/bope-collectors/src/scan.rs`, `src-tauri/src/scan_task.rs`, `views/Scanning.tsx` |
| Horários | Módulo central `src/time.ts`: converte **uma vez** a partir do RFC 3339 recebido; `DD/MM/AAAA HH:mm:ss` no fuso local com deslocamento do próprio instante (horário de verão correto) e UTC abaixo (ou UTC primeiro, em Configurações); valor original em `<time datetime>` e no tooltip; valor não reconhecido é mostrado como veio, marcado. Cada horário tem **tipo** (criação, modificação, acesso, execução, evento, evento de serviço, exclusão, coleta, verificação, início/fim de intervalo…) e **confiabilidade** (exato / aproximado / incerto). O app pergunta ao Rust quais campos são horários (`time_fields`), sem adivinhar pelo formato | `src/time.ts`, `src/ui/TimeValue.tsx`, `bope_core::report_time`, `commands.rs::time_fields` |
| Linha do tempo | Reconstruída: ordem determinística (instante, fonte, campo, local, assunto), sem mesclar eventos, filtros reais (fonte, tipo, confiabilidade, texto, data no fuso exibido), separação por dia, paginação de 200; inclui eventos de serviço e exclusões da Lixeira; fontes não lidas e faixas de cobertura listadas | `views/pages/TimelinePage.tsx` |
| Serviços do Windows | `ServiceSource` só leitura (SCM com `SC_MANAGER_CONNECT` + `SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG`); coletor `windows_service` para PcaSvc, DiagTrack, DPS, SysMain, EventLog: nome interno/exibição, existência, estado, inicialização, conta, caminho, PID, desativado, falha de consulta, horário da coleta, fonte. Histórico separado: eventos 7034/7036/7040/7045 do `System.evtx`, lido como arquivo. Nenhuma regra lê isso; parado nunca é colorido como achado | `bope-host`, `bope-host-windows/src/services.rs`, `bope-parsers/src/evtx.rs`, `bope-collectors/src/windows_service.rs`, `views/pages/ServicesPage.tsx`, ADR 0130 |
| Lixeira | Coletor `recycle_bin`: lista a pasta da conta uma vez, lê cada `$I` (metadados), **nunca abre `$R`**. Resumo sem nomes: horários da pasta, contagens, órfãos, exclusão mais nova/antiga e **"Última modificação observada no artefato"** com a origem (pasta ou entrada), sem inventar um horário global. Por item: `$I`, `$R` presente ou não, caminho original, data de exclusão, horários das entradas. Modo SS: só o resumo e itens do catálogo, com caminhos redigidos | `bope-collectors/src/recycle_bin.rs`, `bope-core/src/view.rs`, `views/pages/RecycleBinPage.tsx`, ADR 0131 |
| Evidências | Estados mantidos (Encontrado/Não encontrado/Não verificado; INFO/SUSPEITO/DETECTADO/CORROBORADO nas ferramentas Roblox), sempre com palavra + forma + cor. Lista em tabela por categoria; painel lateral com título, estados, nível, fonte, descrição, explicações legítimas, observações (caminho/hash/assinatura primeiro, horários tipados), regra e arquivos de código; JSON bruto só em seção recolhida | `views/pages/EvidencePage.tsx`, `views/EvidenceDetails.tsx`, `ui/Badge.tsx` |
| Filtros e volume | Busca, estado, nível, categoria, ordem; filtros de serviços, Lixeira e linha do tempo; paginação de listas longas (observações sem regra, histórico, itens, linha do tempo) | `ui/Paging.tsx` |
| Estados da aplicação | Antes da verificação, iniciando, verificando, cancelando, cancelada, falhou, concluída, carregando relatório, relatório ilegível, fonte não lida (com motivo), lista vazia, filtro sem resultado | `ui/States.tsx`, páginas |
| Relatórios HTML/TXT/PDF/JSON | Mesmo formato de horário da tela, em UTC e no fuso da janela (a CLI usa o fuso do sistema), tipo e confiabilidade na linha do tempo, seções de Serviços (estado na coleta × histórico) e Lixeira (última modificação observada); JSON mantém os valores originais e registra o fuso | `bope-core/src/export.rs`, `report_time.rs` |
| Consentimento/privacidade | Textos do consentimento (CLI e app, 3 idiomas onde existiam) e `PRIVACY.md` descrevem as duas leituras novas | `bope-cli`, locales, `PRIVACY.md` |
| Documentação | ADRs 0130, 0131, 0132; CHANGELOG; seção nova em `docs/bope/validacao-windows.md` | `docs/` |

## Testes executados (resultados reais desta sessão, em Linux)

| Verificação | Resultado |
|---|---|
| `cargo test --workspace --exclude bope-desktop` | **1 100 aprovados**, 0 falhas, 1 ignorado |
| `pnpm test` (interface, vitest + jsdom, fuso America/Sao_Paulo) | **99 aprovados** |
| `pnpm typecheck`, `pnpm lint` (biome) | ok |
| `cargo clippy --all-targets -D warnings` | ok em Linux e no alvo `x86_64-pc-windows-msvc` (inclui `bope-desktop` e o código SCM) |
| `cargo fmt --check` | ok |
| `cargo xtask check-rules / check-baseline / rules-reference --check / check-locales / check-unicode / check-versions` | ok |
| `cargo deny check` | advisories, bans, licenses, sources ok |
| `reuse lint` | 1 112/1 112 arquivos conformes |
| Compilação Windows (`x86_64-pc-windows-gnu`, MinGW-w64) | `bope-scanner.exe` e `bope-scanner-cli.exe` gerados |
| Capturas (Chromium headless, build de produção, IPC simulado) | 10 telas; nenhum erro de console da aplicação (único aviso: o `favicon.ico` pedido automaticamente pelo navegador ao servidor de teste) |

Testes novos cobrem, entre outros: conversão de horários (UTC/local, horário de verão, offsets, valores
inválidos, nunca converter duas vezes, anos < 100, precisão), tipos e confiabilidade (os mesmos casos em
TypeScript e Rust); serviços em execução, parado, desativado, iniciando, não instalado, acesso negado,
configuração negada, consulta falhou, sem histórico, histórico não lido e histórico com horários;
reconhecimento dos eventos 7034/7036/7040/7045; Lixeira com itens, sem `$R`, `$R` sem `$I`, `$I` ilegível,
vazia, ausente, negada, última modificação pela pasta e por entrada, SID nunca guardado; progresso com
módulo atual, pendentes e tempo; navegação bloqueada antes do relatório; ausência do banner e presença da
indicação no Sobre; filtros da linha do tempo (tipo, confiabilidade, data no fuso); relatórios com UTC +
fuso e seções novas.

## Pendências e limitações — leia antes de usar

1. **Nada foi executado num Windows real.** Os executáveis foram compilados, não executados (sem Windows
   nem Wine aqui). A consulta ao Service Control Manager compila e passa no clippy para Windows, mas nunca
   rodou. Siga `docs/bope/validacao-windows.md` (seção nova: navegação, progresso, horários, serviços,
   Lixeira).
2. **Histórico de serviços sem arquivo `.evtx` de teste**: o leitor de eventos 7034/7036/7040/7045 foi
   testado sobre os dados do evento (JSON), não sobre um `System.evtx` real ou sintético. A palavra do
   estado no evento 7036 pode vir traduzida; só inglês e português são reconhecidos — o texto original é
   sempre mostrado.
3. **Capturas**: tiradas no Chromium com IPC simulado e dados sintéticos; o histórico de serviços das
   capturas foi acrescentado à mão. Não são do WebView2 no Windows.
4. **Tailandês**: as telas novas não foram traduzidas para tailandês (419 chaves caem no inglês;
   `check-locales` só avisa). Português e inglês estão completos.
5. **Lixeira**: só a unidade do sistema e só a conta que roda a verificação; correlação com USN/MFT/Amcache
   continua só pelo nome do catálogo (`roblox_trace`), sem correlação nova.
6. **"UNOFFICIAL BUILD"**: removido da faixa do topo, mas mantido em Sobre, nos fatos do relatório e nos
   arquivos exportados, por exigência da licença (NOTICE §7(c)). Removê-lo por completo violaria a licença.
7. Binários não assinados digitalmente (SmartScreen pode avisar).

Nenhuma tela, relatório ou status diz "limpo" ou "culpado"; um serviço parado nunca é marcado como
suspeito.
