// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! Saved reports: JSON, HTML and plain text, each with the SHA-256 of its exact bytes
//! (B.O.P.E, ADR 0116).
//!
//! Every format is built from a [`ReportView`] — so an SS-mode export is redacted exactly as the screen
//! was — and from the bundle's own rule texts. The functions here only build bytes; writing them to a
//! file the person chose is the caller's job, and nothing is ever sent anywhere.
//!
//! **What the hash is.** The SHA-256 of a saved report lets anyone tell later whether those bytes were
//! changed **after** they were hashed. It does not prove that the scan itself was honest, that the PC
//! was not modified to show something else, or who made the report (ADR 0040: reports are not signed).

use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::assessment::{Assessment, Conclusion, Level, ModuleState};
use crate::bundle::Bundle;
use crate::model::{EvidenceState, Mode, Observation, UnmeasuredReason};
use crate::view::ReportView;

/// Name of the format, written into every JSON export.
pub const FORMAT_NAME: &str = "bope-scanner-report";
/// Version of the JSON export's own shape.
pub const FORMAT_VERSION: u32 = 1;

/// One of the three formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Machine-readable, the whole view.
    Json,
    /// A self-contained page for a person.
    Html,
    /// Plain text for a person.
    Text,
}

impl Format {
    /// The file extension.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Html => "html",
            Self::Text => "txt",
        }
    }

    /// Parses `json`, `html` or `txt`/`text`.
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "html" | "htm" => Some(Self::Html),
            "txt" | "text" => Some(Self::Text),
            _ => None,
        }
    }
}

/// A built export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exported {
    /// The exact bytes to write.
    pub bytes: Vec<u8>,
    /// Their SHA-256, lowercase hex.
    pub sha256: String,
    /// The format's extension.
    pub extension: &'static str,
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// The text of a `.sha256` file for `file_name`, in the `sha256sum` format.
pub fn sha256_line(sha256: &str, file_name: &str) -> String {
    format!("{sha256}  {file_name}\n")
}

/// A file name for a report generated at `generated_at` (RFC 3339) in `mode`.
pub fn file_stem(generated_at: &str, mode: Mode) -> String {
    let stamp: String = generated_at
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'T')
        .take(15)
        .collect();
    let mode = match mode {
        Mode::SelfCheck => "self",
        Mode::Ss => "ss",
    };
    format!("bope-report-{stamp}-{mode}")
}

/// Builds one export.
pub fn export(view: &ReportView, bundle: &Bundle, lang: &str, format: Format) -> Exported {
    let bytes = match format {
        Format::Json => json(view, bundle, lang),
        Format::Html => html(view, bundle, lang).into_bytes(),
        Format::Text => text(view, bundle, lang).into_bytes(),
    };
    Exported {
        sha256: sha256_hex(&bytes),
        bytes,
        extension: format.extension(),
    }
}

#[derive(Serialize)]
struct RuleEntry {
    title: String,
    description: String,
    falsepositives: Vec<String>,
    retention: String,
    level: Level,
    category: String,
    collector: String,
}

#[derive(Serialize)]
struct JsonExport<'a> {
    format: &'static str,
    format_version: u32,
    tool: &'static str,
    based_on: &'static str,
    language: &'a str,
    hash_note: &'static str,
    view: &'a ReportView,
    rules: std::collections::BTreeMap<String, RuleEntry>,
}

const HASH_NOTE: &str = "The SHA-256 published beside this file shows whether these bytes changed after it was computed. It does not prove the scan was honest or who made the report.";

fn rule_entries(
    view: &ReportView,
    bundle: &Bundle,
    lang: &str,
) -> std::collections::BTreeMap<String, RuleEntry> {
    let mut out = std::collections::BTreeMap::new();
    for evidence in &view.evidence {
        let Some(sourced) = bundle
            .rules()
            .iter()
            .find(|s| s.rule.id == evidence.rule_id)
        else {
            continue;
        };
        let text = bundle.text(&evidence.rule_id, lang);
        out.insert(
            evidence.rule_id.clone(),
            RuleEntry {
                title: text
                    .as_ref()
                    .map_or_else(|| sourced.rule.title.clone(), |t| t.title.clone()),
                description: text.as_ref().map_or_else(
                    || sourced.rule.description.clone(),
                    |t| t.description.clone(),
                ),
                falsepositives: text.as_ref().map_or_else(
                    || sourced.rule.falsepositives.clone(),
                    |t| t.falsepositives.clone(),
                ),
                retention: text
                    .as_ref()
                    .map_or_else(|| sourced.rule.retention.clone(), |t| t.retention.clone()),
                level: sourced.rule.assessment_level(),
                category: sourced.rule.assessment_category(),
                collector: sourced.rule.collector.clone(),
            },
        );
    }
    out
}

fn json(view: &ReportView, bundle: &Bundle, lang: &str) -> Vec<u8> {
    let export = JsonExport {
        format: FORMAT_NAME,
        format_version: FORMAT_VERSION,
        tool: "B.O.P.E Scanner",
        based_on: "aeterna-rongroi (GPL-3.0-or-later); modified version, not an official aeterna-rongroi build",
        language: lang,
        hash_note: HASH_NOTE,
        view,
        rules: rule_entries(view, bundle, lang),
    };
    let mut bytes = serde_json::to_vec_pretty(&export).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// Portuguese label of a category id.
pub fn category_label(category: &str) -> &'static str {
    match category {
        "roblox_tools" => "Ferramentas Roblox conhecidas",
        "fastflags" => "FastFlags e configurações",
        "roblox" => "Roblox e executores",
        "processes_memory" => "Processos e memória",
        "execution" => "Artefatos de execução",
        "files" => "Arquivos e metadados",
        "persistence" => "Registro e persistência",
        "drivers" => "Drivers e DLLs",
        "macros_peripherals" => "Macros e periféricos",
        "usb_devices" => "USB e dispositivos",
        "browser_scripts" => "Navegadores e scripts",
        "network" => "Rede",
        "system_logs" => "Logs do sistema",
        "firmware_boot" => "Firmware e inicialização",
        _ => "Outros indicadores",
    }
}

/// Portuguese label of a `roblox_trace` status.
pub fn tool_status_label(status: &str) -> &'static str {
    match status {
        "corroborated" => "CORROBORADO",
        "detected" => "DETECTADO",
        "suspected" => "SUSPEITO",
        _ => "INFO",
    }
}

/// Portuguese label of a `roblox_trace` source state.
pub fn source_state_label(state: &str) -> &'static str {
    match state {
        "measured" => "lida",
        "not_applicable" => "não se aplica (só na verificação avançada)",
        "error" => "erro de leitura",
        _ => "não verificada",
    }
}

/// Portuguese label of an evidence class.
pub fn evidence_class_label(class: &str) -> &'static str {
    match class {
        "execution" => "execução registrada",
        "running" => "em execução",
        "process_interaction" => "módulo no player do Roblox",
        "inventory" => "inventário (não prova execução)",
        "reference" => "referência histórica",
        "file_history" => "histórico do sistema de arquivos",
        "deleted" => "exclusão registrada",
        "current_file" => "arquivo presente",
        "archive_content" => "dentro de arquivo compactado",
        "executor_layout" => "estrutura de executor",
        "executor_scripts" => "scripts com APIs de executor",
        "installation" => "instalação",
        "persistence" => "inicialização automática",
        "client_configuration" => "configuração do cliente",
        _ => "outro",
    }
}

fn field<'a>(o: &'a Observation, name: &str) -> &'a str {
    o.fields
        .get(name)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
}

fn flag(o: &Observation, name: &str) -> bool {
    o.fields.get(name).and_then(serde_json::Value::as_bool) == Some(true)
}

fn tool_line(o: &Observation) -> String {
    let families = field(o, "families");
    let mut parts = vec![format!(
        "{} [{}] — fontes independentes: {}{}",
        field(o, "display"),
        tool_status_label(field(o, "status")),
        o.fields
            .get("families_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        if families.is_empty() {
            String::new()
        } else {
            format!(" ({families})")
        }
    )];
    let classes: Vec<&str> = field(o, "classes")
        .split(", ")
        .filter(|c| !c.is_empty())
        .map(evidence_class_label)
        .collect();
    if !classes.is_empty() {
        parts.push(format!("evidências: {}", classes.join("; ")));
    }
    if flag(o, "missing_now") {
        parts.push("arquivo citado não está mais no caminho registrado".to_owned());
    }
    if flag(o, "common_legitimate") {
        parts.push("ferramenta de uso legítimo comum".to_owned());
    }
    let (first, last) = (field(o, "first_seen"), field(o, "last_seen"));
    if !first.is_empty() {
        parts.push(format!("de {first} a {last} (UTC)"));
    }
    parts.join(" · ")
}

fn hit_line(o: &Observation) -> String {
    let exists = match o.fields.get("exists").and_then(serde_json::Value::as_bool) {
        Some(true) => " · existe hoje",
        Some(false) => " · não está no caminho hoje",
        None => "",
    };
    let path = field(o, "path");
    format!(
        "{} {} · {} · {}{}{}",
        field(o, "time"),
        field(o, "source"),
        evidence_class_label(field(o, "evidence_class")),
        if path.is_empty() {
            field(o, "name")
        } else {
            path
        },
        exists,
        if field(o, "matched_on") == "parent_folder" {
            " · nome da pasta"
        } else {
            ""
        }
    )
}

/// Portuguese label of a module state.
pub fn state_label(state: ModuleState) -> &'static str {
    match state {
        ModuleState::Ok => "OK",
        ModuleState::Info => "INFO",
        ModuleState::Warn => "WARN",
        ModuleState::Flag => "FLAG",
        ModuleState::NotChecked => "NÃO VERIFICADO",
    }
}

/// Portuguese text of the conclusion.
pub fn conclusion_label(conclusion: Conclusion) -> &'static str {
    match conclusion {
        Conclusion::NoSuspiciousEvidence => "Sem evidências suspeitas nas fontes examinadas",
        Conclusion::Inconclusive => "Inconclusivo",
        Conclusion::ManualReview => "Requer revisão manual",
        Conclusion::Corroborated => "Múltiplos indicadores corroborados",
        Conclusion::HighConfidence => "Evidência de alta confiança que exige análise do checker",
    }
}

/// What the conclusion does and does not mean.
pub fn conclusion_note(conclusion: Conclusion) -> &'static str {
    match conclusion {
        Conclusion::NoSuspiciousEvidence => {
            "Nenhum indicador definido foi encontrado nas fontes que puderam ser lidas. Isto NÃO é uma declaração de que o PC está limpo: um software não vê outro PC, hardware DMA, firmware comprometido nem um Windows reinstalado."
        }
        Conclusion::Inconclusive => {
            "Fontes demais não puderam ser examinadas (por exemplo, sem direitos de administrador) para que a ausência de alertas signifique algo."
        }
        Conclusion::ManualReview => {
            "Uma única fonte mostra algo que merece análise humana. Leia as explicações legítimas listadas antes de concluir qualquer coisa."
        }
        Conclusion::Corroborated => {
            "Indicadores vieram de duas ou mais fontes independentes. Ainda assim, cada um tem explicações legítimas que precisam ser consideradas."
        }
        Conclusion::HighConfidence => {
            "Um indicador específico (FLAG) foi corroborado por outra fonte independente. Isto exige análise do checker; não é uma condenação automática."
        }
    }
}

/// Portuguese text of a caveat key.
pub fn caveat_label(key: &str) -> &'static str {
    match key {
        "software_only" => {
            "Verificação feita por software dentro do Windows: não detecta cheats em outro PC, dispositivos DMA que imitam hardware comum, firmware comprometido ou vestígios removidos por reinstalação do sistema."
        }
        "not_elevated" => {
            "A verificação rodou sem direitos de administrador; várias fontes não puderam ser lidas."
        }
        "standard_tier" => {
            "Verificação padrão: as fontes da verificação avançada (navegadores, arquivos do usuário, MRUs, comandos do PowerShell) não foram lidas."
        }
        "categories_not_checked" => "Algumas categorias não puderam ser verificadas nesta máquina.",
        _ => "",
    }
}

fn level_label(level: Level) -> &'static str {
    match level {
        Level::Info => "INFO",
        Level::Warn => "WARN",
        Level::Flag => "FLAG",
    }
}

/// Portuguese text of an unmeasured reason.
pub fn reason_label(reason: UnmeasuredReason) -> &'static str {
    match reason {
        UnmeasuredReason::NotWindows => "não está rodando no Windows",
        UnmeasuredReason::NotOnThisOs => "esta versão do Windows não guarda este registro",
        UnmeasuredReason::NotAdmin => "o Windows exige direitos de administrador para mostrar isto",
        UnmeasuredReason::NotAttempted => "não foi lido: a verificação parou antes de chegar aqui",
        UnmeasuredReason::AccessDenied => "o Windows recusou a abertura",
        UnmeasuredReason::ServiceDisabled => {
            "o serviço do Windows que escreve este registro está desligado"
        }
        UnmeasuredReason::SourceAbsent => "este PC não tem esse registro",
        UnmeasuredReason::SourceEmpty => "o local existe e está vazio",
        UnmeasuredReason::Partial => "parte foi lida e parte não",
        UnmeasuredReason::BudgetSpent => {
            "este programa parou de ler antes de terminar (limite de tempo)"
        }
        UnmeasuredReason::ReadFailed => "não foi possível ler",
        UnmeasuredReason::CollectorUnavailable => "esta versão não lê isso",
        UnmeasuredReason::NotConsented => "só a verificação avançada lê isso",
        UnmeasuredReason::OtherVolume => {
            "está em outra unidade; só o journal da unidade do sistema é lido"
        }
    }
}

fn title_of(bundle: &Bundle, rule_id: &str, lang: &str) -> String {
    bundle
        .text(rule_id, lang)
        .map(|t| t.title)
        .or_else(|| {
            bundle
                .rules()
                .iter()
                .find(|s| s.rule.id == rule_id)
                .map(|s| s.rule.title.clone())
        })
        .unwrap_or_else(|| rule_id.to_owned())
}

fn observation_line(observation: &Observation) -> String {
    observation
        .fields
        .iter()
        .map(|(k, v)| match v {
            serde_json::Value::String(s) => format!("{k}={s}"),
            other => format!("{k}={other}"),
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

fn assessment_of(view: &ReportView) -> Option<&Assessment> {
    view.assessment.as_ref()
}

#[allow(clippy::too_many_lines)]
fn text(view: &ReportView, bundle: &Bundle, lang: &str) -> String {
    let mut out = String::new();
    let h = &view.header;
    let _ = writeln!(out, "B.O.P.E Scanner — relatório de verificação");
    let _ = writeln!(
        out,
        "Baseado em aeterna-rongroi (GPL-3.0-or-later). Versão modificada: NÃO é uma build oficial do aeterna-rongroi."
    );
    let _ = writeln!(out, "{}", "=".repeat(78));
    let _ = writeln!(out, "Versão da ferramenta : {}", h.provenance.version);
    let _ = writeln!(
        out,
        "Regras               : {} regras, SHA-256 {}",
        h.rules_bundle.rule_count, h.rules_bundle.sha256
    );
    let _ = writeln!(out, "Gerado em (UTC)      : {}", h.generated_at);
    let _ = writeln!(
        out,
        "Fuso dos horários    : UTC (todos os horários deste relatório)"
    );
    let _ = writeln!(
        out,
        "Windows              : {} {}",
        h.platform,
        h.os_build.clone().unwrap_or_default()
    );
    let _ = writeln!(
        out,
        "Administrador        : {}",
        match h.elevated {
            Some(true) => "sim",
            Some(false) => "não",
            None => "desconhecido",
        }
    );
    let _ = writeln!(
        out,
        "Tipo de verificação  : {}",
        match h.scan_tier {
            crate::model::ScanTier::Standard => "padrão",
            crate::model::ScanTier::Full => "avançada",
        }
    );
    let _ = writeln!(
        out,
        "Modo                 : {}",
        match view.mode {
            Mode::SelfCheck => "próprio (tudo visível)",
            Mode::Ss => "screenshare (filtrado e com caminhos ocultos)",
        }
    );
    let _ = writeln!(out);
    if let Some(a) = assessment_of(view) {
        let _ = writeln!(out, "CONCLUSÃO: {}", conclusion_label(a.conclusion));
        let _ = writeln!(out, "  {}", conclusion_note(a.conclusion));
        let _ = writeln!(
            out,
            "  Fontes independentes com alerta: {} (com FLAG: {})",
            a.independent_sources, a.flag_sources
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "MÓDULOS");
        for c in &a.categories {
            let partial = if c.partial { " (parcial)" } else { "" };
            let _ = writeln!(
                out,
                "  [{:<14}] {}{} — {} verificadas, {} não verificadas",
                state_label(c.state),
                category_label(&c.category),
                partial,
                c.measured,
                c.unmeasured
            );
        }
        let _ = writeln!(out);
        if !a.supporting.is_empty() {
            let _ = writeln!(out, "EVIDÊNCIAS QUE SUSTENTAM A CONCLUSÃO");
            for f in &a.supporting {
                let when = match (&f.earliest, &f.latest) {
                    (Some(a), Some(b)) if a != b => format!(" — {a} a {b}"),
                    (Some(a), _) => format!(" — {a}"),
                    _ => String::new(),
                };
                let _ = writeln!(
                    out,
                    "  [{}] {} (fonte: {}){when}",
                    level_label(f.level),
                    title_of(bundle, &f.rule_id, lang),
                    f.source
                );
            }
            for p in &a.proximity {
                let _ = writeln!(
                    out,
                    "  Proximidade temporal ({} min): \"{}\" e \"{}\" — proximidade não é causalidade.",
                    p.seconds / 60,
                    title_of(bundle, &p.a, lang),
                    title_of(bundle, &p.b, lang)
                );
            }
            let _ = writeln!(out);
        }
        let _ = writeln!(out, "LIMITAÇÕES");
        for c in &a.caveats {
            let _ = writeln!(out, "  - {}", caveat_label(c));
        }
        let _ = writeln!(out);
    }
    let tools = &view.roblox_tools;
    if !tools.tools.is_empty() || !tools.sources.is_empty() {
        let _ = writeln!(out, "FERRAMENTAS ROBLOX (correlação de todas as fontes)");
        if tools.tools.is_empty() {
            let _ = writeln!(
                out,
                "  Nenhum nome do catálogo nas fontes lidas. Isto vale só para as fontes abaixo."
            );
        }
        for o in &tools.tools {
            let _ = writeln!(out, "  - {}", tool_line(o));
        }
        if !tools.hits.is_empty() {
            let _ = writeln!(out, "  Rastros (horários em UTC):");
            for o in &tools.hits {
                let _ = writeln!(out, "    • {}", hit_line(o));
            }
        }
        let _ = writeln!(out, "  Fontes:");
        for o in &tools.sources {
            let reason = field(o, "reason");
            let _ = writeln!(
                out,
                "    {:<20} {}{}",
                field(o, "source"),
                source_state_label(field(o, "state")),
                if reason.is_empty() {
                    String::new()
                } else {
                    format!(" ({reason})")
                }
            );
        }
        let _ = writeln!(
            out,
            "  Status: INFO = nome/contexto; SUSPEITO = nome de executor/injetor sem execução; DETECTADO = execução, estrutura, scripts ou módulo; CORROBORADO = DETECTADO em 2+ famílias independentes. Nenhum status é veredito."
        );
        let _ = writeln!(out);
    }
    let _ = writeln!(
        out,
        "EVIDÊNCIAS ({} encontradas · {} não encontradas · {} não verificadas)",
        view.listed.found, view.listed.not_found, view.listed.unmeasured
    );
    let _ = writeln!(out, "{}", "-".repeat(78));
    let mut evidence: Vec<_> = view.evidence.iter().collect();
    evidence.sort_by_key(|e| match e.state {
        EvidenceState::Found { .. } => 0,
        EvidenceState::Unmeasured { .. } => 1,
        EvidenceState::NotFound { .. } => 2,
    });
    for e in evidence {
        let rule_text = bundle.text(&e.rule_id, lang);
        let title = title_of(bundle, &e.rule_id, lang);
        match &e.state {
            EvidenceState::Found { observations } => {
                let _ = writeln!(out, "[ENCONTRADO] {title}");
                for o in observations {
                    let _ = writeln!(out, "    • {}", observation_line(o));
                }
                if let Some(t) = &rule_text {
                    let _ = writeln!(out, "    Sobre: {}", t.description);
                    let _ = writeln!(
                        out,
                        "    Explicações legítimas: {}",
                        t.falsepositives.join("; ")
                    );
                    let _ = writeln!(out, "    Profundidade da fonte: {}", t.retention);
                }
            }
            EvidenceState::NotFound { .. } => {
                let _ = writeln!(out, "[NÃO ENCONTRADO] {title}");
            }
            EvidenceState::Unmeasured { reason, .. } => {
                let _ = writeln!(out, "[NÃO VERIFICADO] {title} — {}", reason_label(*reason));
            }
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "LINHA DO TEMPO ({} registros; horários em UTC; ordem de horários registrados não é ordem de eventos)",
        view.timeline.entries.len()
    );
    for entry in view.timeline.entries.iter().take(500) {
        let _ = writeln!(
            out,
            "  {}  {:<20} {:<16} {}",
            entry.at,
            entry
                .collector
                .clone()
                .unwrap_or_else(|| "âncora".to_owned()),
            entry.field,
            entry.subject.clone().unwrap_or_default()
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Somente evidências. Este relatório não prova que um PC está limpo nem que alguém trapaceou."
    );
    let _ = writeln!(
        out,
        "Hash: o SHA-256 publicado ao lado deste arquivo mostra se ele foi alterado depois de calculado; não prova sozinho a autenticidade da coleta."
    );
    out
}

/// Escapes text for HTML.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn state_class(state: ModuleState) -> &'static str {
    match state {
        ModuleState::Ok => "ok",
        ModuleState::Info => "info",
        ModuleState::Warn => "warn",
        ModuleState::Flag => "flag",
        ModuleState::NotChecked => "na",
    }
}

const CSS: &str = "body{font:14px/1.5 system-ui,Segoe UI,sans-serif;margin:0;background:#0f1216;color:#e6e9ee}main{max-width:1100px;margin:0 auto;padding:24px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px;border-bottom:1px solid #2a313b;padding-bottom:4px}.muted{color:#9aa4b2}.banner{padding:14px 16px;border-radius:8px;margin:16px 0;border:1px solid #2a313b;background:#161b22}.banner strong{font-size:17px}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid #222a33;vertical-align:top}.chip{display:inline-block;min-width:54px;text-align:center;font-weight:700;font-size:12px;padding:2px 8px;border-radius:999px}.ok{background:#12351f;color:#7ee2a0}.info{background:#13283f;color:#8cc4ff}.warn{background:#3d3010;color:#ffd166}.flag{background:#3f1418;color:#ff8a8a}.na{background:#2a2f36;color:#b9c2cc}.ev{border:1px solid #2a313b;border-radius:8px;padding:10px 12px;margin:8px 0;background:#141920}.obs{font-family:Consolas,monospace;font-size:12px;color:#c9d1d9;white-space:pre-wrap;word-break:break-all}.small{font-size:12px}footer{margin:32px 0 8px;color:#9aa4b2;font-size:12px}";

#[allow(clippy::too_many_lines)]
fn html(view: &ReportView, bundle: &Bundle, lang: &str) -> String {
    let h = &view.header;
    let mut out = String::new();
    let _ = write!(
        out,
        "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Relatório B.O.P.E Scanner</title><style>{CSS}</style></head><body><main>"
    );
    let _ = write!(
        out,
        "<h1>B.O.P.E Scanner — relatório de verificação</h1><div class=\"muted small\">Baseado em aeterna-rongroi (GPL-3.0-or-later). Versão modificada, não é build oficial do aeterna-rongroi.</div>"
    );
    let _ = write!(
        out,
        "<table class=\"small\" style=\"margin-top:12px\"><tr><th>Versão</th><td>{}</td><th>Gerado em</th><td>{} (UTC; todos os horários em UTC)</td></tr><tr><th>Regras</th><td>{} · SHA-256 <code>{}</code></td><th>Windows</th><td>{} {}</td></tr><tr><th>Administrador</th><td>{}</td><th>Verificação</th><td>{} · modo {}</td></tr></table>",
        escape(&h.provenance.version),
        escape(&h.generated_at),
        h.rules_bundle.rule_count,
        escape(&h.rules_bundle.sha256),
        escape(&h.platform),
        escape(&h.os_build.clone().unwrap_or_default()),
        match h.elevated {
            Some(true) => "sim",
            Some(false) => "não",
            None => "desconhecido",
        },
        match h.scan_tier {
            crate::model::ScanTier::Standard => "padrão",
            crate::model::ScanTier::Full => "avançada",
        },
        match view.mode {
            Mode::SelfCheck => "próprio",
            Mode::Ss => "screenshare",
        }
    );
    if let Some(a) = assessment_of(view) {
        let top = a
            .categories
            .iter()
            .map(|c| c.state)
            .max()
            .unwrap_or(ModuleState::NotChecked);
        let _ = write!(
            out,
            "<div class=\"banner\"><span class=\"chip {}\">{}</span> <strong>{}</strong><div class=\"muted\">{}</div><div class=\"small\">Fontes independentes com alerta: {} · com FLAG: {}</div></div>",
            state_class(top),
            state_label(top),
            escape(conclusion_label(a.conclusion)),
            escape(conclusion_note(a.conclusion)),
            a.independent_sources,
            a.flag_sources
        );
        let _ = write!(out, "<h2>Módulos</h2><table>");
        for c in &a.categories {
            let _ = write!(
                out,
                "<tr><td><span class=\"chip {}\">{}</span></td><td>{}{}</td><td class=\"muted small\">{} verificadas · {} não verificadas</td></tr>",
                state_class(c.state),
                state_label(c.state),
                escape(category_label(&c.category)),
                if c.partial {
                    " <span class=\"muted\">(parcial)</span>"
                } else {
                    ""
                },
                c.measured,
                c.unmeasured
            );
        }
        let _ = write!(out, "</table>");
        if !a.supporting.is_empty() {
            let _ = write!(
                out,
                "<h2>Evidências que sustentam a conclusão</h2><table><tr><th>Nível</th><th>Regra</th><th>Fonte</th><th>Horários</th></tr>"
            );
            for f in &a.supporting {
                let lvl = match f.level {
                    Level::Flag => "flag",
                    Level::Warn => "warn",
                    Level::Info => "info",
                };
                let _ = write!(
                    out,
                    "<tr><td><span class=\"chip {lvl}\">{}</span></td><td>{}</td><td>{}</td><td class=\"small\">{} {}</td></tr>",
                    level_label(f.level),
                    escape(&title_of(bundle, &f.rule_id, lang)),
                    escape(&f.source),
                    escape(&f.earliest.clone().unwrap_or_default()),
                    escape(&f.latest.clone().unwrap_or_default())
                );
            }
            let _ = write!(out, "</table>");
            for p in &a.proximity {
                let _ = write!(
                    out,
                    "<p class=\"small\">Proximidade temporal de {} min entre \"{}\" e \"{}\" — proximidade não é causalidade.</p>",
                    p.seconds / 60,
                    escape(&title_of(bundle, &p.a, lang)),
                    escape(&title_of(bundle, &p.b, lang))
                );
            }
        }
        let _ = write!(out, "<h2>Limitações</h2><ul>");
        for c in &a.caveats {
            let _ = write!(out, "<li>{}</li>", escape(caveat_label(c)));
        }
        let _ = write!(out, "</ul>");
    }
    let tools = &view.roblox_tools;
    if !tools.tools.is_empty() || !tools.sources.is_empty() {
        let _ = write!(
            out,
            "<h2>Ferramentas Roblox</h2><p class=\"muted small\">Correlação de todas as fontes lidas. INFO = nome/contexto; SUSPEITO = nome de executor/injetor sem execução; DETECTADO = execução, estrutura, scripts ou módulo; CORROBORADO = DETECTADO em duas ou mais famílias independentes. Nenhum status é veredito.</p>"
        );
        if tools.tools.is_empty() {
            let _ = write!(
                out,
                "<p>Nenhum nome do catálogo nas fontes lidas. Isto vale só para as fontes listadas.</p>"
            );
        } else {
            let _ = write!(out, "<ul>");
            for o in &tools.tools {
                let _ = write!(out, "<li>{}</li>", escape(&tool_line(o)));
            }
            let _ = write!(out, "</ul>");
        }
        if !tools.hits.is_empty() {
            let _ = write!(
                out,
                "<h3>Rastros</h3><p class=\"muted small\">Horários em UTC. “Não está no caminho hoje” não quer dizer excluído.</p><ul class=\"small\">"
            );
            for o in &tools.hits {
                let _ = write!(out, "<li>{}</li>", escape(&hit_line(o)));
            }
            let _ = write!(out, "</ul>");
        }
        let _ = write!(out, "<h3>Fontes</h3><table class=\"small\">");
        for o in &tools.sources {
            let _ = write!(
                out,
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(field(o, "source")),
                escape(source_state_label(field(o, "state"))),
                escape(field(o, "reason"))
            );
        }
        let _ = write!(out, "</table>");
    }
    let _ = write!(
        out,
        "<h2>Evidências</h2><p class=\"muted small\">{} encontradas · {} não encontradas · {} não verificadas</p>",
        view.listed.found, view.listed.not_found, view.listed.unmeasured
    );
    let mut evidence: Vec<_> = view.evidence.iter().collect();
    evidence.sort_by_key(|e| match e.state {
        EvidenceState::Found { .. } => 0,
        EvidenceState::Unmeasured { .. } => 1,
        EvidenceState::NotFound { .. } => 2,
    });
    for e in evidence {
        let title = escape(&title_of(bundle, &e.rule_id, lang));
        let text = bundle.text(&e.rule_id, lang);
        match &e.state {
            EvidenceState::Found { observations } => {
                let _ = write!(
                    out,
                    "<div class=\"ev\"><span class=\"chip warn\">ENCONTRADO</span> <strong>{title}</strong>"
                );
                for o in observations {
                    let _ = write!(
                        out,
                        "<div class=\"obs\">{}</div>",
                        escape(&observation_line(o))
                    );
                }
                if let Some(t) = text {
                    let _ = write!(
                        out,
                        "<p class=\"small\">{}</p><p class=\"small\"><b>Explicações legítimas:</b> {}</p><p class=\"small muted\"><b>Profundidade da fonte:</b> {}</p>",
                        escape(&t.description),
                        escape(&t.falsepositives.join("; ")),
                        escape(&t.retention)
                    );
                }
                let _ = write!(out, "</div>");
            }
            EvidenceState::NotFound { .. } => {
                let _ = write!(
                    out,
                    "<div class=\"ev\"><span class=\"chip ok\">NÃO ENCONTRADO</span> {title}</div>"
                );
            }
            EvidenceState::Unmeasured { reason, .. } => {
                let _ = write!(
                    out,
                    "<div class=\"ev\"><span class=\"chip na\">NÃO VERIFICADO</span> {title} <span class=\"muted small\">— {}</span></div>",
                    escape(reason_label(*reason))
                );
            }
        }
    }
    let _ = write!(
        out,
        "<h2>Linha do tempo</h2><p class=\"muted small\">Horários em UTC. Ordem de horários registrados não é ordem de eventos; um registro ausente não foi necessariamente apagado.</p><table class=\"small\">"
    );
    for entry in view.timeline.entries.iter().take(1000) {
        let _ = write!(
            out,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(&entry.at),
            escape(
                &entry
                    .collector
                    .clone()
                    .unwrap_or_else(|| "âncora".to_owned())
            ),
            escape(&entry.field),
            escape(&entry.subject.clone().unwrap_or_default())
        );
    }
    let _ = writeln!(
        out,
        "</table><footer>Somente evidências. Este relatório não prova que um PC está limpo nem que alguém trapaceou. O SHA-256 publicado ao lado deste arquivo mostra se ele foi alterado depois de calculado; não prova sozinho a autenticidade da coleta.</footer></main></body></html>"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_lowercase_hex_of_the_exact_bytes() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_line("ab", "r.json"), "ab  r.json\n");
    }

    #[test]
    fn html_escapes_everything_read_from_the_machine() {
        assert_eq!(
            escape("<script>\"x\" & 'y'"),
            "&lt;script&gt;&quot;x&quot; &amp; &#39;y&#39;"
        );
    }

    #[test]
    fn file_names_carry_the_time_and_the_mode() {
        assert_eq!(
            file_stem("2026-10-15T12:34:56Z", Mode::Ss),
            "bope-report-20261015T123456-ss"
        );
        assert_eq!(Format::parse("TXT"), Some(Format::Text));
        assert_eq!(Format::parse("pdf"), None);
    }
}
