import { useMemo } from "react";
import { ShieldAlert, Bug, ServerCrash, Zap, ChevronLeft } from "lucide-react";
import { HostRecord, Severity, Vuln } from "../api";
import NetworkPanel from "./NetworkPanel";

const faNum = (n: number) => n.toLocaleString("fa-IR");

const SEV_FA: Record<Severity, string> = {
  Critical: "بحرانی", High: "بالا", Medium: "متوسط", Low: "پایین", Info: "اطلاعاتی",
};
const SEV_COLOR: Record<Severity, string> = {
  Critical: "#ff3b3b", High: "#ff8c00", Medium: "#f5c518", Low: "#2ea043", Info: "#6b7280",
};
const SEV_ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

// A finding paired with the host it was found on, so the dashboard can link
// straight to that host.
interface Finding { host: HostRecord; vuln: Vuln }

/**
 * The customer's overview, shown before any search is run. Everything here is
 * computed from the hosts the backend already scoped to this account, so the
 * dashboard needs no extra request and can never show another tenant's data.
 */
export default function Dashboard({ hosts, onSearch }: {
  hosts: HostRecord[];
  onSearch: (q: string) => void;
}) {
  const summary = useMemo(() => {
    const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 } as Record<Severity, number>;
    const cves = new Set<string>();
    const exploitable: Finding[] = [];
    let openPorts = 0;

    for (const host of hosts) {
      openPorts += host.ports.length;
      for (const vuln of host.vulns) {
        bySeverity[vuln.severity] = (bySeverity[vuln.severity] ?? 0) + 1;
        if (vuln.cve && vuln.cve !== "N/A") cves.add(vuln.cve);
        if (vuln.exploitAvailable) exploitable.push({ host, vuln });
      }
    }

    // Weaponised first, then malware-linked, then by CVSS.
    exploitable.sort((a, b) =>
      Number(b.vuln.exploitedByMalware) - Number(a.vuln.exploitedByMalware) ||
      (b.vuln.exploitFrameworks?.length ?? 0) - (a.vuln.exploitFrameworks?.length ?? 0) ||
      b.vuln.cvss - a.vuln.cvss);

    const riskiest = [...hosts]
      .map(h => ({
        host: h,
        critical: h.vulns.filter(v => v.severity === "Critical").length,
        exploits: h.vulns.filter(v => v.exploitAvailable).length,
      }))
      .filter(r => r.critical > 0 || r.exploits > 0)
      .sort((a, b) => b.exploits - a.exploits || b.critical - a.critical)
      .slice(0, 6);

    return {
      bySeverity,
      openPorts,
      cves: cves.size,
      exploitable,
      exploitableHosts: new Set(exploitable.map(e => e.host.ip)).size,
      riskiest,
    };
  }, [hosts]);

  const totalFindings = SEV_ORDER.reduce((a, s) => a + summary.bySeverity[s], 0);

  return (
    <div className="space-y-3">
      {/* ── headline counters ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Stat label="میزبان‌های اسکن‌شده" value={faNum(hosts.length)} onClick={() => onSearch("*")} />
        <Stat label="یافته‌های بحرانی" value={faNum(summary.bySeverity.Critical)} tone="#ff3b3b"
              onClick={() => onSearch("has:critical")} />
        <Stat label="دارای اکسپلویت" value={faNum(summary.exploitable.length)} tone="#ff3b3b"
              hint={`روی ${faNum(summary.exploitableHosts)} میزبان`}
              onClick={() => onSearch("has:exploit")} />
        <Stat label="مجموع CVEها" value={faNum(summary.cves)} />
      </div>

      {/* ── severity spread ── */}
      {totalFindings > 0 && (
        <div className="bg-card border border-border rounded p-4">
          <div className="flex items-center gap-2 mb-3">
            <Bug size={13} className="text-primary" />
            <span className="text-xs font-semibold text-foreground">توزیع شدت آسیب‌پذیری‌ها</span>
            <span className="ms-auto text-[11px] text-muted-foreground">{faNum(totalFindings)} یافته</span>
          </div>
          <div className="h-2 rounded-sm overflow-hidden flex bg-secondary mb-3" dir="ltr">
            {SEV_ORDER.map(s => summary.bySeverity[s] > 0 && (
              <div key={s} title={`${SEV_FA[s]}: ${faNum(summary.bySeverity[s])}`}
                   style={{ width: `${(summary.bySeverity[s] / totalFindings) * 100}%`, background: SEV_COLOR[s] }} />
            ))}
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-1.5">
            {SEV_ORDER.map(s => (
              <span key={s} className="flex items-center gap-1.5 text-[12px] text-muted-foreground">
                <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ background: SEV_COLOR[s] }} />
                {SEV_FA[s]}
                <span className="font-mono text-foreground tabular-nums">{faNum(summary.bySeverity[s])}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── findings with a published exploit ── */}
      <div className="bg-card border border-border rounded overflow-hidden">
        <div className="px-4 py-2.5 border-b border-border bg-secondary/20 flex items-center gap-2">
          <Zap size={13} className="text-[#ff3b3b]" />
          <span className="text-xs font-semibold text-foreground">آسیب‌پذیری‌های دارای اکسپلویت</span>
          {summary.exploitable.length > 0 && (
            <span className="ms-auto text-[11px] text-muted-foreground">
              {faNum(summary.exploitable.length)} یافته — اولویت اول رفع
            </span>
          )}
        </div>

        {summary.exploitable.length === 0 ? (
          <p className="px-4 py-6 text-center text-[12px] text-muted-foreground">
            هیچ آسیب‌پذیری با اکسپلویت منتشرشده‌ای در اسکن‌های شما یافت نشد.
          </p>
        ) : (
          <div className="divide-y divide-border">
            {summary.exploitable.slice(0, 6).map(({ host, vuln }) => (
              <button key={`${host.ip}-${vuln.pluginId}`} onClick={() => onSearch(host.ip)}
                className="w-full text-start px-4 py-3 hover:bg-secondary/20 transition-colors flex items-start gap-3">
                <span className="w-1 self-stretch rounded-sm flex-shrink-0"
                      style={{ background: SEV_COLOR[vuln.severity] }} />
                <div className="flex-1 min-w-0">
                  <p className="text-[13px] text-foreground leading-snug truncate" dir="ltr" style={{ textAlign: "start" }}>
                    {vuln.name}
                  </p>
                  <div className="flex flex-wrap items-center gap-2 mt-1.5">
                    <span className="text-[12px] font-mono text-primary" dir="ltr">{host.ip}</span>
                    {vuln.cve !== "N/A" && (
                      <span className="text-[11px] font-mono text-muted-foreground" dir="ltr">{vuln.cve}</span>
                    )}
                    <ExploitBadges vuln={vuln} />
                  </div>
                </div>
                <ChevronLeft size={13} className="text-muted-foreground flex-shrink-0 mt-1" />
              </button>
            ))}
            {summary.exploitable.length > 6 && (
              <button onClick={() => onSearch("has:exploit")}
                className="w-full px-4 py-2.5 text-[12px] text-primary hover:bg-secondary/20 transition-colors">
                مشاهدهٔ همهٔ {faNum(summary.exploitable.length)} یافته
              </button>
            )}
          </div>
        )}
      </div>

      {/* ── hosts that need attention first ── */}
      {summary.riskiest.length > 0 && (
        <div className="bg-card border border-border rounded overflow-hidden">
          <div className="px-4 py-2.5 border-b border-border bg-secondary/20 flex items-center gap-2">
            <ServerCrash size={13} className="text-[#ff8c00]" />
            <span className="text-xs font-semibold text-foreground">میزبان‌های پرخطر</span>
          </div>
          <div className="divide-y divide-border">
            {summary.riskiest.map(({ host, critical, exploits }) => (
              <button key={host.ip} onClick={() => onSearch(host.ip)}
                className="w-full text-start px-4 py-2.5 hover:bg-secondary/20 transition-colors flex items-center gap-3">
                <span className="text-[13px] font-mono text-primary" dir="ltr">{host.ip}</span>
                {host.hostnames[0] && (
                  <span className="text-[11px] text-muted-foreground truncate hidden sm:block" dir="ltr">
                    {host.hostnames[0]}
                  </span>
                )}
                <span className="ms-auto flex items-center gap-3 flex-shrink-0">
                  {exploits > 0 && (
                    <span className="flex items-center gap-1 text-[11px] text-[#ff3b3b]">
                      <Zap size={10} /> {faNum(exploits)}
                    </span>
                  )}
                  {critical > 0 && (
                    <span className="flex items-center gap-1 text-[11px] text-[#ff3b3b]">
                      <ShieldAlert size={10} /> {faNum(critical)}
                    </span>
                  )}
                  <span className="text-[11px] text-muted-foreground">{faNum(host.ports.length)} پورت</span>
                </span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ── where the hosts actually live ── */}
      <NetworkPanel hosts={hosts} onSearch={onSearch} />
    </div>
  );
}

// ── shared bits ─────────────────────────────────────────────────────────────

export function ExploitBadges({ vuln }: { vuln: Vuln }) {
  if (!vuln.exploitAvailable && !vuln.exploitedByMalware) return null;
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      {vuln.exploitAvailable && (
        <span className="inline-flex items-center gap-1 text-[11px] text-[#ff3b3b] border border-[#ff3b3b]/30 bg-[#ff3b3b]/5 rounded px-1.5 py-0.5">
          <Zap size={9} /> اکسپلویت موجود
        </span>
      )}
      {vuln.exploitedByMalware && (
        <span className="inline-flex items-center gap-1 text-[11px] text-[#ff8c00] border border-[#ff8c00]/30 bg-[#ff8c00]/5 rounded px-1.5 py-0.5">
          <Bug size={9} /> بهره‌برداری توسط بدافزار
        </span>
      )}
      {vuln.exploitEase === "no-exploit-needed" && (
        <span className="text-[11px] text-[#ff3b3b] border border-[#ff3b3b]/30 bg-[#ff3b3b]/5 rounded px-1.5 py-0.5">
          بدون نیاز به اکسپلویت
        </span>
      )}
      {vuln.exploitFrameworks?.map(f => (
        <span key={f} className="text-[11px] font-mono text-muted-foreground border border-border rounded px-1.5 py-0.5" dir="ltr">
          {f}
        </span>
      ))}
    </span>
  );
}

// A tile without an onClick is a plain readout — the CVE count has no search
// that would narrow to it.
function Stat({ label, value, tone, hint, onClick }: {
  label: string; value: string; tone?: string; hint?: string; onClick?: () => void;
}) {
  return (
    <button onClick={onClick} disabled={!onClick}
      className="bg-card border border-border rounded px-3 py-3 text-center transition-colors enabled:hover:border-primary/30 enabled:hover:bg-secondary/20 disabled:cursor-default">
      <div className="text-xl font-bold tabular-nums" style={{ color: tone ?? "var(--primary)" }}>{value}</div>
      <div className="text-[11px] text-muted-foreground mt-0.5">{label}</div>
      {hint && <div className="text-[10px] text-muted-foreground/70 mt-0.5">{hint}</div>}
    </button>
  );
}
