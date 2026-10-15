// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// The scan as it happens: real progress, the module running, what each finished module found, and a
// way to stop (B.O.P.E, ADR 0115). Everything shown comes from `scan_status`; nothing is estimated.

import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { cancelScan, scanStatus } from "../api";
import type { AppInfo, RuleMeta, RuleText, ScanStatus } from "../types";

/** How often the window asks Rust where the scan is. */
export const POLL_MS = 400;

interface Props {
  info: AppInfo | null;
  meta: Record<string, RuleMeta>;
  texts: Record<string, RuleText>;
  onFinished: (state: "done" | "cancelled" | "failed", message: string | null) => void;
}

export function Scanning({ info, meta, texts, onFinished }: Props) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const finished = useRef(false);

  useEffect(() => {
    let alive = true;
    const tick = () => {
      void scanStatus()
        .then((next) => {
          if (!alive) {
            return;
          }
          setStatus(next);
          if (
            !finished.current &&
            (next.state === "done" || next.state === "cancelled" || next.state === "failed")
          ) {
            finished.current = true;
            onFinished(next.state, next.message);
          }
        })
        .catch(() => {});
    };
    tick();
    const timer = setInterval(tick, POLL_MS);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [onFinished]);

  const steps = status?.steps ?? [];
  const total = status?.total ?? info?.collectors.length ?? 0;
  const done = steps.length;
  const percent = total > 0 ? Math.round((done / total) * 100) : 0;
  const next = info?.collectors[done]?.id;
  const found = steps.flatMap((step) =>
    step.found_rules
      .filter((id) => !meta[id]?.selector)
      .map((id) => ({ id, collector: step.collector, level: meta[id]?.level ?? "info" })),
  );

  return (
    <section
      className="scanning"
      aria-labelledby="scanning-title"
      aria-busy={status?.state === "running"}
    >
      <h2 id="scanning-title">{t("scan.title")}</h2>
      <div
        className="progress"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={done}
        aria-label={t("scan.progress_label")}
      >
        <div className="progress-fill" style={{ width: `${percent}%` }} />
      </div>
      <p className="progress-text">
        {t("scan.progress", { done, total, percent })}
        {status?.state === "running" && next && (
          <>
            {" "}
            <span className="current">
              {t("scan.current", { module: t(`report:collector.${next}`, { defaultValue: next }) })}
            </span>
          </>
        )}
      </p>
      {status?.state === "running" && (
        <button
          type="button"
          className="danger"
          disabled={cancelling}
          onClick={() => {
            setCancelling(true);
            void cancelScan();
          }}
        >
          {cancelling ? t("scan.cancelling") : t("scan.cancel")}
        </button>
      )}

      <div className="scan-columns">
        <section aria-labelledby="modules-title">
          <h3 id="modules-title">{t("scan.modules")}</h3>
          <ol className="module-log">
            {steps.map((step) => (
              <li key={step.collector} className={`step step-${step.state}`}>
                <span className="step-name">
                  {t(`report:collector.${step.collector}`, { defaultValue: step.collector })}
                </span>
                <span className="step-state">
                  {step.state === "measured"
                    ? t("scan.measured", { observations: step.observations })
                    : step.state === "not_consented"
                      ? t("scan.not_consented")
                      : t("scan.unmeasured", {
                          reason: t(`report:reason.${step.reason ?? "read_failed"}`),
                        })}
                  {step.gaps > 0 && ` · ${t("scan.gaps", { gaps: step.gaps })}`}
                </span>
                <span className="step-time muted">{(step.elapsed_ms / 1000).toFixed(1)} s</span>
              </li>
            ))}
          </ol>
        </section>
        <section aria-labelledby="live-title">
          <h3 id="live-title">{t("scan.live")}</h3>
          {found.length === 0 ? (
            <p className="muted">{t("scan.live_none")}</p>
          ) : (
            <ul className="live-findings">
              {found.map((item) => (
                <li key={item.id}>
                  <span className={`chip chip-${item.level}`}>{t(`level.${item.level}`)}</span>{" "}
                  {texts[item.id]?.title ?? item.id}
                </li>
              ))}
            </ul>
          )}
          <p className="muted small">{t("scan.live_note")}</p>
        </section>
      </div>
    </section>
  );
}
