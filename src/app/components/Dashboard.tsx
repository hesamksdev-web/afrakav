import { useMemo } from "react";
import {
  ShieldAlert, ShieldCheck, Bug, ServerCrash, Zap, ChevronLeft, CalendarCheck,
  Repeat2, Wifi, FolderTree, TrendingDown, Server,
} from "lucide-react";
import { EstateSnapshot, HostRecord, Severity, Vuln } from "../api";
import { faNum, faDate, timeAgo } from "../format";
import { SEV_COLOR, SEV_FA, SEV_ORDER, sevRank, worstSeverity } from "./severity";
import { hostsByWorstSeverity, topFamilies, topRepeatedFindings, topServices } from "./insights";
import BarList from "./BarList";
import SeverityChart from "./SeverityChart";
import TrendChart from "./TrendChart";
import NetworkPanel from "./NetworkPanel";

/** When the customer's network was last scanned, and how many scans there have
 *  been. Deliberately not the newest scan's own host count: that file may
 *  cover a slice of the estate, and printing it beside the total host tile
 *  reads as a contradiction. */
export interface ScanStatus {
  at: string;
  count: number;
}

// A finding paired with the host it was found on, so the dashboard can link
// straight to that host.
interface Finding { host: HostRecord; vuln: Vuln }

/**
 * The customer's overview, shown before any search is run. Everything here is
 * computed from the hosts the backend already scoped to this account, so the
 * dashboard needs no extra request and can never show another tenant's data.
 */
export default function Dashboard({ hosts, onSearch, scan, trend }: {
  hosts: HostRecord[];
  onSearch: (q: string) => void;
  scan: ScanStatus | null;
  trend: EstateSnapshot[];
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

    // Ranked by what is worst on each host, not filtered to criticals only.
    // An estate whose findings are all medium still has a "fix these first"
    // list, and the old threshold left those customers staring at nothing.
    const riskiest = [...hosts]
      .map(h => ({
        host: h,
        worst: worstSeverity(h.vulns),
        findings: h.vulns.length,
        critical: h.vulns.filter(v => v.severity === "Critical").length,
        exploits: h.vulns.filter(v => v.exploitAvailable).length,
      }))
      .filter(r => r.findings > 0)
      .sort((a, b) =>
        b.exploits - a.exploits ||
        (b.worst ? sevRank(b.worst) : 0) - (a.worst ? sevRank(a.worst) : 0) ||
        b.findings - a.findings)
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

  const repeated = useMemo(() => topRepeatedFindings(hosts), [hosts]);
  const hostRisk = useMemo(() => hostsByWorstSeverity(hosts), [hosts]);
  const services = useMemo(() => topServices(hosts), [hosts]);
  const families = useMemo(() => topFamilies(hosts), [hosts]);

  return (
    <div className="space-y-3">
      {/* ── proof the scan actually ran ──
          This stays at the top whether or not anything was found: a customer
          with a clean network needs to see that the network was looked at. */}
      <ScanBanner scan={scan} />

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

      {/* ── is it getting better? ── */}
      <Panel icon={<TrendingDown size={13} className="text-primary" />}
             title="روند آسیب‌پذیری‌ها"
             meta={trend.length >= 2 ? `${faNum(trend.length)} اسکن` : undefined}>
        <TrendChart points={trend} />
      </Panel>

      {/* ── how bad are the findings, and how much of the estate is involved ──
          Two different questions, so two charts: one counts findings, the
          other counts hosts. */}
      <div className="grid md:grid-cols-2 gap-3">
        <Panel icon={<Bug size={13} className="text-primary" />}
               title="توزیع شدت آسیب‌پذیری‌ها"
               meta={totalFindings > 0 ? `${faNum(totalFindings)} یافته` : undefined}>
          {totalFindings === 0 ? (
            <div className="flex items-start gap-2.5 text-[12px] text-muted-foreground leading-relaxed">
              <ShieldCheck size={14} className="text-[#2ea043] flex-shrink-0 mt-0.5" />
              <p>
                هیچ آسیب‌پذیری‌ای روی میزبان‌های شما ثبت نشده است. اسکن انجام شده و
                {" "}{faNum(hosts.length)} میزبان بررسی شده‌اند.
              </p>
            </div>
          ) : (
            <SeverityChart counts={summary.bySeverity} total={totalFindings} onSearch={onSearch} />
          )}
        </Panel>

        <Panel icon={<Server size={13} className="text-primary" />}
               title="وضعیت میزبان‌ها"
               meta={`${faNum(hosts.length)} میزبان`}>
          <BarList data={hostRisk} labelWidth="8.5rem" onSearch={onSearch} />
        </Panel>
      </div>

      {/* ── the work list ──
          The same finding on many hosts is one fix, not many. This is usually
          the shortest path from "۱۹ یافته" to "۴ کار". */}
      {repeated.length > 0 && (
        <Panel icon={<Repeat2 size={13} className="text-primary" />}
               title="یافته‌های تکرارشونده"
               meta="بر اساس تعداد میزبان درگیر">
          <BarList data={repeated} labelWidth="14rem" onSearch={onSearch} />
        </Panel>
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
            {summary.riskiest.map(({ host, worst, findings, exploits }) => (
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
                  {worst && (
                    <span className="flex items-center gap-1 text-[11px]" style={{ color: SEV_COLOR[worst] }}>
                      <ShieldAlert size={10} /> {SEV_FA[worst]}
                    </span>
                  )}
                  <span className="text-[11px] text-muted-foreground">{faNum(findings)} یافته</span>
                  <span className="text-[11px] text-muted-foreground hidden sm:block">
                    {faNum(host.ports.length)} پورت
                  </span>
                </span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ── what the attack surface is made of, and what kind of problem it is ── */}
      <div className="grid md:grid-cols-2 gap-3">
        <Panel icon={<Wifi size={13} className="text-primary" />}
               title="سرویس‌های در معرض"
               meta="بر اساس تعداد میزبان">
          {services.length === 0 ? (
            <p className="text-[12px] text-muted-foreground">پورت بازی ثبت نشده است.</p>
          ) : (
            <BarList data={services} labelWidth="7rem" onSearch={onSearch} />
          )}
        </Panel>

        <Panel icon={<FolderTree size={13} className="text-primary" />}
               title="دسته‌بندی یافته‌ها"
               meta="خانوادهٔ پلاگین">
          {families.length === 0 ? (
            <p className="text-[12px] text-muted-foreground">یافته‌ای برای دسته‌بندی وجود ندارد.</p>
          ) : (
            <BarList data={families} labelWidth="9rem" onSearch={onSearch} />
          )}
        </Panel>
      </div>

      {/* ── where the hosts actually live ── */}
      <NetworkPanel hosts={hosts} onSearch={onSearch} />
    </div>
  );
}

// ── shared bits ─────────────────────────────────────────────────────────────

/** Every chart panel on the dashboard has the same head, so it is one object
 *  rather than the same markup written out six times. */
function Panel({ icon, title, meta, children }: {
  icon: React.ReactNode;
  title: string;
  meta?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-card border border-border rounded p-4">
      <div className="flex items-center gap-2 mb-3">
        {icon}
        <span className="text-xs font-semibold text-foreground">{title}</span>
        {meta && <span className="ms-auto text-[11px] text-muted-foreground">{meta}</span>}
      </div>
      {children}
    </div>
  );
}

/**
 * States plainly when the network was last scanned. An empty findings list is
 * ambiguous on its own — it reads the same whether the network is clean or
 * nothing ever ran — so the date is what turns "no vulnerabilities" into
 * something the customer can trust.
 */
export function ScanBanner({ scan }: { scan: ScanStatus | null }) {
  if (!scan) return null;
  return (
    <div className="bg-card border border-border rounded px-4 py-3 flex items-center gap-3">
      <CalendarCheck size={15} className="text-primary flex-shrink-0" />
      <div className="min-w-0">
        <p className="text-xs text-foreground">
          آخرین اسکن شبکهٔ شما: <span className="font-semibold">{faDate(scan.at)}</span>
          <span className="text-muted-foreground"> — {timeAgo(scan.at)}</span>
        </p>
        <p className="text-[11px] text-muted-foreground mt-0.5">
          تاکنون {faNum(scan.count)} اسکن برای شبکهٔ شما انجام شده است.
        </p>
      </div>
    </div>
  );
}

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
