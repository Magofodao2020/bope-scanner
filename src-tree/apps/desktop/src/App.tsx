// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

// Start → scan → results (B.O.P.E, ADR 0115). The person chooses and consents before anything is read,
// watches the scan, and then reads the frozen report.

import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { appInfo, ruleMeta, ruleTexts, startScan } from "./api";
import { languageNames, supportedLanguages } from "./i18n";
import type { AppInfo, Mode, ReportHeader, RuleMeta, RuleText, SsOptions } from "./types";
import { About } from "./views/About";
import { Home, type ScanChoice } from "./views/Home";
import { Report } from "./views/Report";
import { Scanning } from "./views/Scanning";
import { UnofficialBanner } from "./views/UnofficialBanner";

type Screen =
  | { kind: "home" }
  | { kind: "scanning"; choice: ScanChoice }
  | { kind: "report"; mode: Mode; options?: SsOptions }
  | { kind: "cancelled" }
  | { kind: "failed"; message: string | null }
  | { kind: "busy" };

/** The facts About & code shows, from what the start screen already read. */
function headerOf(info: AppInfo): ReportHeader {
  return {
    schema_version: 1,
    provenance: {
      official: info.official,
      version: info.version,
      commit: null,
      exe_sha256: info.exe_sha256,
    },
    rules_bundle: info.rules,
    platform: info.platform,
    os_build: info.os_build,
    elevated: info.elevated,
    generated_at: "",
    boot_time: { state: "unmeasured", reason: "not_attempted" },
  };
}

export function App() {
  const { t, i18n } = useTranslation();
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [infoFailed, setInfoFailed] = useState(false);
  const [meta, setMeta] = useState<Record<string, RuleMeta>>({});
  const [texts, setTexts] = useState<Record<string, RuleText>>({});
  const [screen, setScreen] = useState<Screen>({ kind: "home" });
  const [about, setAbout] = useState(false);

  useEffect(() => {
    void appInfo()
      .then(setInfo)
      .catch(() => setInfoFailed(true));
    void ruleMeta()
      .then(setMeta)
      .catch(() => {});
  }, []);

  useEffect(() => {
    void ruleTexts(i18n.language)
      .then(setTexts)
      .catch(() => {});
  }, [i18n.language]);

  const choice = screen.kind === "scanning" ? screen.choice : null;
  const onFinished = useCallback(
    (state: "done" | "cancelled" | "failed", message: string | null) => {
      if (state === "done" && choice) {
        setScreen({ kind: "report", mode: choice.mode, options: choice.options });
      } else if (state === "cancelled") {
        setScreen({ kind: "cancelled" });
      } else {
        setScreen({ kind: "failed", message });
      }
    },
    [choice],
  );

  return (
    <main>
      <header className="top">
        <div className="brand">
          <h1>{t("app.name")}</h1>
          <p className="muted">{t("app.tagline")}</p>
        </div>
        <div className="top-actions">
          <button type="button" className="nav" onClick={() => setAbout(true)}>
            {t("nav.about")}
          </button>
          <label className="language">
            {t("language.label")}{" "}
            <select
              value={i18n.language}
              onChange={(e) => void i18n.changeLanguage(e.target.value)}
            >
              {supportedLanguages.map((lang) => (
                <option key={lang} value={lang}>
                  {languageNames[lang]}
                </option>
              ))}
            </select>
          </label>
        </div>
      </header>

      {info && !info.official && <UnofficialBanner />}

      {about && (
        <About
          header={info ? headerOf(info) : null}
          headerFailed={infoFailed}
          onBack={() => setAbout(false)}
        />
      )}

      <div hidden={about}>
        {screen.kind === "home" && (
          <Home
            info={info}
            infoFailed={infoFailed}
            onStart={(next) => {
              setScreen({ kind: "busy" });
              void startScan(next.tier)
                .then((started) =>
                  setScreen(
                    started
                      ? { kind: "scanning", choice: next }
                      : { kind: "failed", message: t("scan.already") },
                  ),
                )
                .catch((reason: unknown) => setScreen({ kind: "failed", message: String(reason) }));
            }}
          />
        )}

        {screen.kind === "scanning" && (
          <Scanning info={info} meta={meta} texts={texts} onFinished={onFinished} />
        )}

        {screen.kind === "cancelled" && (
          <section>
            <h2>{t("scan.cancelled_title")}</h2>
            <p>{t("scan.cancelled_body")}</p>
          </section>
        )}

        {screen.kind === "failed" && (
          <section>
            <h2>{t("scan.failed_title")}</h2>
            <p>{t("scan.failed_body")}</p>
            {screen.message && <p className="note">{screen.message}</p>}
          </section>
        )}

        {screen.kind === "report" && (
          <Report
            mode={screen.mode}
            options={screen.options}
            onBack={() => setScreen({ kind: "home" })}
          />
        )}
      </div>

      <footer className="muted">{t("footer.evidence_only")}</footer>
    </main>
  );
}
