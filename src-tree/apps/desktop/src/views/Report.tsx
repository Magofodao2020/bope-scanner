// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { ageTexts, codeLinks, reportView, ruleMeta, ruleTexts } from "../api";
import { type Filters, filterEvidence, NO_FILTERS, type SortOrder, sortEvidence } from "../filters";
import { type EvidenceGroup, groupEvidence, type StateFilter } from "../grouping";
import { withKeys } from "../keys";
import type {
  AgeText,
  BootTime,
  CodeLinks,
  Evidence,
  Mode,
  Observation,
  ReportView,
  RowBand,
  RuleMeta,
  RuleText,
  SsOptions,
} from "../types";
import { AssessmentPanel } from "./AssessmentPanel";
import { EvidenceRow } from "./EvidenceRow";
import { ExportPanel } from "./ExportPanel";
import { CATEGORY_ORDER } from "./Home";
import { ReportSummary } from "./ReportSummary";
import { RobloxToolsPanel } from "./RobloxToolsPanel";
import { Timeline } from "./Timeline";
import { CrossSource, TraceAges } from "./TraceAges";

interface Props {
  mode: Mode;
  /** What the player agreed SS mode may show beyond its default (ADR 0052). */
  options?: SsOptions;
  onBack: () => void;
}

export function Report({ mode, options, onBack }: Props) {
  const { t, i18n } = useTranslation("report");
  const [view, setView] = useState<ReportView | null>(null);
  const [texts, setTexts] = useState<Record<string, RuleText>>({});
  const [ages, setAges] = useState<Record<string, AgeText>>({});
  const [links, setLinks] = useState<CodeLinks | null>(null);
  const [filter, setFilter] = useState<StateFilter | null>(null);
  const [technicalAll, setTechnicalAll] = useState(false);
  const [meta, setMeta] = useState<Record<string, RuleMeta>>({});
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [sort, setSort] = useState<SortOrder>("category");

  useEffect(() => {
    // Without the levels and categories the panel falls back to grouping by collector.
    void ruleMeta()
      .then(setMeta)
      .catch(() => {});
  }, []);

  useEffect(() => {
    void reportView(mode, options).then(setView);
  }, [mode, options]);

  useEffect(() => {
    void ruleTexts(i18n.language).then(setTexts);
  }, [i18n.language]);

  useEffect(() => {
    // A failed call leaves the retention texts out; the rows themselves still show (ADR 0061).
    void ageTexts(i18n.language)
      .then(setAges)
      .catch(() => {});
  }, [i18n.language]);

  useEffect(() => {
    // Carried fix (b): a failed call leaves `links` at `null`, the same as one still in flight —
    // both mean "not known yet", never a build guessed to be one thing or the other.
    void codeLinks()
      .then(setLinks)
      .catch(() => {});
  }, []);

  if (!view) {
    return null;
  }
  const { header } = view;
  const rights =
    header.elevated === null
      ? t("header.elevated_unknown")
      : header.elevated
        ? t("header.elevated_yes")
        : t("header.elevated_no");
  const fileBase = links?.commit ? `${links.repository}/blob/${links.commit}` : null;
  const treeBase = links?.commit ? `${links.repository}/tree/${links.commit}` : null;
  // Carried fix (b): whether `codeLinks()` has arrived at all, independent of what it said.
  const linksKnown = links !== null;
  const official = header.provenance.official;
  const hasMeta = Object.keys(meta).length > 0;
  const kept = hasMeta ? filterEvidence(view.evidence, filters, meta, texts) : view.evidence;
  const groups: (EvidenceGroup & { label: string })[] = !hasMeta
    ? groupEvidence(kept, filter, view.collector_order).map((group) => ({
        ...group,
        label: t(`collector.${group.collector}`, { defaultValue: group.collector }),
      }))
    : sort === "category"
      ? [...CATEGORY_ORDER].flatMap((category) => {
          const rows = sortEvidence(
            kept.filter(
              (item) =>
                (meta[item.rule_id]?.category ?? "other") === category &&
                (filter === null || item.state === filter),
            ),
            "severity",
            meta,
          );
          return rows.length === 0
            ? []
            : [{ collector: `category-${category}`, rows, label: t(`category.${category}`) }];
        })
      : [
          {
            collector: `sorted-${sort}`,
            rows: sortEvidence(
              kept.filter((item) => filter === null || item.state === filter),
              sort,
              meta,
            ),
            label: t(`sort.${sort}`),
          },
        ].filter((group) => group.rows.length > 0);

  return (
    <section className="report">
      {view.assessment && (
        <AssessmentPanel
          assessment={view.assessment}
          texts={texts}
          category={filters.category}
          onCategory={(category) => setFilters((current) => ({ ...current, category }))}
        />
      )}

      {view.roblox_tools && <RobloxToolsPanel tools={view.roblox_tools} />}

      <ReportSummary listed={view.listed} filter={filter} onFilter={setFilter} />

      <dl className="facts context">
        <dt>{mode === "ss" ? t("header.mode_ss") : t("header.mode_self")}</dt>
        <dd />
        <dt>{t("header.scan_tier")}</dt>
        <dd>{header.scan_tier === "full" ? t("header.tier_full") : t("header.tier_standard")}</dd>
        <dt>{t("header.version")}</dt>
        <dd>{header.provenance.version}</dd>
        <dt>{t("header.platform")}</dt>
        <dd>{[header.platform, header.os_build].filter(Boolean).join(" ")}</dd>
        <dt>{t("header.rights")}</dt>
        <dd>{rights}</dd>
        {/* One line of context for reading every time below it, with the sentence that stops a start
            days ago being read as something the player did (ADR 0039). */}
        <dt>{t("header.boot_time")}</dt>
        <dd>
          <BootTimeValue bootTime={header.boot_time} />
        </dd>
        <dt>{t("header.rules")}</dt>
        <dd>
          {header.rules_bundle.rule_count} · <code>{header.rules_bundle.sha256.slice(0, 12)}</code>
        </dd>
      </dl>

      {/* Facts about the scan, not about the machine: each applies to every rule it stopped, so it
          is stated once here rather than as a row per rule (ADR 0027, ADR 0030). */}
      {view.scope.not_admin > 0 && (
        <p className="scope">{t("scope.not_admin", { checks: view.scope.not_admin })}</p>
      )}
      {view.scope.not_attempted > 0 && (
        <p className="scope">{t("scope.not_attempted", { checks: view.scope.not_attempted })}</p>
      )}
      {(view.scope.not_consented ?? 0) > 0 && (
        <p className="scope">
          {t("scope.not_consented", { checks: view.scope.not_consented ?? 0 })}
        </p>
      )}
      {mode === "ss" && header.scan_tier === "full" && !options?.server_identity && (
        <p className="muted">{t("header.server_identity_hidden")}</p>
      )}
      {mode === "ss" && header.scan_tier === "full" && !options?.download_host && (
        <p className="muted">{t("header.download_host_hidden")}</p>
      )}

      {hasMeta && (
        <div className="finder">
          <label className="search">
            {t("finder.search")}
            <input
              type="search"
              value={filters.search}
              placeholder={t("finder.search_placeholder")}
              onChange={(event) =>
                setFilters((current) => ({ ...current, search: event.target.value }))
              }
            />
          </label>
          <label>
            {t("finder.level")}
            <select
              value={filters.level}
              onChange={(event) =>
                setFilters((current) => ({
                  ...current,
                  level: event.target.value as Filters["level"],
                }))
              }
            >
              <option value="all">{t("finder.level_all")}</option>
              <option value="flag">{t("common:level.flag")}</option>
              <option value="warn">{t("common:level.warn")}</option>
              <option value="info">{t("common:level.info")}</option>
            </select>
          </label>
          <label>
            {t("finder.sort")}
            <select value={sort} onChange={(event) => setSort(event.target.value as SortOrder)}>
              <option value="category">{t("sort.category")}</option>
              <option value="severity">{t("sort.severity")}</option>
              <option value="time">{t("sort.time")}</option>
            </select>
          </label>
          {filters.category && (
            <button
              type="button"
              className="disclosure"
              onClick={() => setFilters((current) => ({ ...current, category: null }))}
            >
              {t("finder.clear_category", { category: t(`category.${filters.category}`) })}
            </button>
          )}
        </div>
      )}

      <div className="toolbar">
        {filter ? (
          <p className="muted">
            {t("toolbar.filtered")}{" "}
            <button type="button" className="disclosure" onClick={() => setFilter(null)}>
              {t("toolbar.clear")}
            </button>
          </p>
        ) : (
          <span />
        )}
        <label className="switch">
          <input
            type="checkbox"
            checked={technicalAll}
            onChange={(event) => setTechnicalAll(event.target.checked)}
          />{" "}
          {t("toolbar.technical_all")}
        </label>
      </div>

      {view.evidence.length === 0 && <p>{t("empty")}</p>}
      {/* A count of 0 is still a filter; choosing it says so rather than showing nothing. */}
      {view.evidence.length > 0 && groups.length === 0 && (
        <p className="muted">{t("toolbar.filtered_empty")}</p>
      )}
      {groups.map((group) => (
        <Group
          key={group.collector}
          group={group}
          texts={texts}
          bands={view.row_bands ?? {}}
          fileBase={fileBase}
          treeBase={treeBase}
          linksKnown={linksKnown}
          official={official}
          technicalAll={technicalAll}
          unfold={filter === "not_found" || sort !== "category"}
        />
      ))}

      {/* After the evidence and apart from it: the times this view may show, in order (ADR 0051). */}
      {/* Above the timeline, in both modes, only when its conditions hold (ADR 0061 section 3). */}
      <CrossSource statements={view.cross_source ?? []} />

      <Timeline timeline={view.timeline} texts={texts} />

      {/* Beside the timeline, in both modes (ADR 0061). */}
      {view.trace_ages && <TraceAges ages={view.trace_ages} texts={ages} />}

      {/* Apart from the evidence, and shown in both modes: this is what the program itself left in
          what the collectors saw, not evidence about the PC (ADR 0010). */}
      {view.own_traces.length > 0 && (
        <section className="own-traces" aria-labelledby="own-traces-title">
          <h3 id="own-traces-title">{t("own_traces.title")}</h3>
          <details>
            <summary className="muted">{t("own_traces.note")}</summary>
            <ul className="observations">
              {withKeys(
                view.own_traces,
                (entry) => `${entry.collector}:${fieldsOf(entry.observation)}`,
              ).map(([key, entry]) => (
                <li key={key}>
                  <span className="muted">({entry.collector})</span>
                  <div className="detail">{fieldsOf(entry.observation)}</div>
                </li>
              ))}
            </ul>
          </details>
        </section>
      )}

      {/* After the evidence and the own traces: what the collectors saw that no rule matched. Self
          mode lists it; in SS mode the list is empty and it is counted below instead (ADR 0014). */}
      {view.unmatched.length > 0 && (
        <section className="unmatched" aria-labelledby="unmatched-title">
          <h3 id="unmatched-title">{t("unmatched.title")}</h3>
          <details>
            <summary className="muted">{t("unmatched.note")}</summary>
            <ul className="observations">
              {withKeys(
                view.unmatched.flatMap((group) =>
                  group.observations.map((observation) => ({
                    collector: group.collector,
                    observation,
                  })),
                ),
                ({ collector, observation }) => `${collector}:${fieldsOf(observation)}`,
              ).map(([key, { collector, observation }]) => (
                <li key={key}>
                  <span className="muted">({collector})</span>
                  <div className="detail">{fieldsOf(observation)}</div>
                </li>
              ))}
            </ul>
          </details>
        </section>
      )}

      {mode === "ss" && (
        <p className="muted">
          {t("hidden", {
            notFound: view.hidden.not_found,
            unmeasuredExpected: view.hidden.unmeasured_expected,
            unmeasuredUnexpected: view.hidden.unmeasured_unexpected,
            unmatched: view.hidden.unmatched,
          })}
        </p>
      )}

      <ExportPanel mode={mode} options={options} />

      <button type="button" onClick={onBack}>
        {t("common:actions.back")}
      </button>
    </section>
  );
}

function Group({
  group,
  texts,
  bands,
  fileBase,
  treeBase,
  linksKnown,
  official,
  technicalAll,
  unfold,
}: {
  group: EvidenceGroup & { label: string };
  texts: Record<string, RuleText>;
  bands: Record<string, RowBand>;
  fileBase: string | null;
  treeBase: string | null;
  linksKnown: boolean;
  official: boolean;
  technicalAll: boolean;
  unfold: boolean;
}) {
  const { t } = useTranslation("report");
  const [showNotFound, setShowNotFound] = useState(false);
  const notFound = group.rows.filter((item) => item.state === "not_found");
  const others = group.rows.filter((item) => item.state !== "not_found");
  const counts = (["found", "unmeasured", "not_found"] as const)
    .map((state) => [state, group.rows.filter((item) => item.state === state).length] as const)
    .filter(([, count]) => count > 0)
    .map(([state, count]) => t(`group_count.${state}`, { count }))
    .join(" · ");
  const titleId = `group-${group.collector}`;
  const row = (item: Evidence) => (
    <EvidenceRow
      key={item.rule_id}
      item={item}
      text={texts[item.rule_id]}
      band={bands[item.rule_id]}
      fileBase={fileBase}
      treeBase={treeBase}
      linksKnown={linksKnown}
      official={official}
      technicalAll={technicalAll}
    />
  );
  return (
    <section className="group" aria-labelledby={titleId}>
      <div className="group-head">
        <h3 id={titleId}>{group.label}</h3>
        <span className="muted counts">{counts}</span>
      </div>
      <ul className="rows">
        {others.map(row)}
        {notFound.length > 0 &&
          (showNotFound || technicalAll || unfold ? (
            notFound.map(row)
          ) : (
            <li>
              <button type="button" className="fold" onClick={() => setShowNotFound(true)}>
                <span className="mark mark-not_found" aria-hidden="true" />
                {t("fold_not_found", { count: notFound.length })}
              </button>
            </li>
          ))}
      </ul>
    </section>
  );
}

function BootTimeValue({ bootTime }: { bootTime: BootTime }) {
  const { t } = useTranslation("report");
  if (bootTime.state === "unmeasured") {
    return <>{t("header.boot_time_unmeasured", { reason: t(`reason.${bootTime.reason}`) })}</>;
  }
  const seconds = bootTime.seconds_since_boot;
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  const since =
    days > 0
      ? t("header.elapsed_days", { days, hours, minutes })
      : t("header.elapsed", { hours, minutes });
  return (
    <>
      {t("header.boot_time_value", { at: bootTime.booted_at, since })}{" "}
      <span className="muted">{t("header.boot_time_note")}</span>
    </>
  );
}

/** One observation as a line of `field=value`, the way both trailing lists show it. */
function fieldsOf(observation: Observation): string {
  return Object.entries(observation.fields)
    .map(([key, value]) => `${key}=${String(value)}`)
    .join(", ");
}
