import { useState, useEffect, useMemo } from "react";
import {
  Search, AlertTriangle, X,
  ChevronDown, ChevronUp, CheckCircle, ShieldCheck,
  Cpu, Wifi, ExternalLink, Tag, Activity,
  Building, LogOut, Loader2, Zap, ArrowRight, LayoutDashboard, SlidersHorizontal,
} from "lucide-react";
import {
  fetchHosts, fetchScans, fetchTrend, fetchAttack, safeHref,
  EstateAttack, EstateSnapshot, HostRecord, Severity,
} from "./api";
import { AuthProvider, useAuth } from "./auth";
import { faNum, timeAgo } from "./format";
import Login from "./Login";
import Admin from "./Admin";
import Dashboard, { ExploitBadges, ScanBanner, ScanStatus } from "./components/Dashboard";
import Brand from "./components/Brand";
import ThemeToggle from "./components/ThemeToggle";
import AttackPanel from "./components/AttackPanel";
import Settings from "./Settings";

const SVCBG: Record<string, string> = {
  http: "text-blue-400", https: "text-cyan-400", "http-alt": "text-blue-400",
  "https-alt": "text-cyan-400", ssh: "text-green-400", mysql: "text-yellow-400",
  postgresql: "text-sky-400", redis: "text-red-400", smtp: "text-pink-400",
  submission: "text-pink-400", imaps: "text-indigo-400", imap: "text-indigo-400",
  "netbios-ssn": "text-purple-400", "microsoft-ds": "text-purple-400",
  msrpc: "text-gray-400", wsman: "text-gray-400", "jenkins-agent": "text-amber-400",
};
const svcCls = (s: string) => SVCBG[s] ?? "text-gray-400";

type Sev = Severity;
const SEV: Record<Sev, { color: string; bg: string; border: string; hex: string }> = {
  Critical: { color: "text-[#ff3b3b]", bg: "bg-[#ff3b3b]/10", border: "border-[#ff3b3b]/30", hex: "#ff3b3b" },
  High:     { color: "text-[#ff8c00]", bg: "bg-[#ff8c00]/10", border: "border-[#ff8c00]/30", hex: "#ff8c00" },
  Medium:   { color: "text-[#f5c518]", bg: "bg-[#f5c518]/10", border: "border-[#f5c518]/30", hex: "#f5c518" },
  Low:      { color: "text-[#2ea043]", bg: "bg-[#2ea043]/10", border: "border-[#2ea043]/30", hex: "#2ea043" },
  Info:     { color: "text-[#8b949e]", bg: "bg-[#8b949e]/10", border: "border-[#8b949e]/30", hex: "#8b949e" },
};

// Persian display names for severities (the English values stay as data keys).
const SEV_FA: Record<Sev, string> = {
  Critical: "بحرانی",
  High: "بالا",
  Medium: "متوسط",
  Low: "پایین",
  Info: "اطلاعاتی",
};

function SevBadge({ s }: { s: Sev }) {
  const c = SEV[s];
  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-[11px] font-bold rounded border ${c.color} ${c.bg} ${c.border}`}>
      <span className="w-1 h-1 rounded-full" style={{ background: c.hex }} />{SEV_FA[s]}
    </span>
  );
}

// ── Brand nav (shared) ─────────────────────────────────────────────────────
/** 10.20.30.11 → 10.20.30.0/24; anything that is not a dotted quad is passed through. */
function subnetLabel(ip: string) {
  const parts = ip.split(".");
  return parts.length === 4 ? `${parts.slice(0, 3).join(".")}.0/24` : ip;
}

/** Whether a failed search was someone looking up an address, so the empty
 *  state can say something specific instead of a generic "not found". */
function looksLikeIp(q: string) {
  return /^\d{1,3}(\.\d{1,3}){1,3}$/.test(q.trim());
}

function BrandNav({ username, onLogout, onSettings, maxW = "max-w-5xl" }: {
  username?: string; onLogout: () => void; onSettings: () => void; maxW?: string;
}) {
  return (
    <nav className="border-b border-border bg-card">
      <div className={`${maxW} mx-auto px-4 py-3 flex items-center gap-6`}>
        <div className="flex items-center gap-2">
          <Brand className="h-7" />
          <span className="text-[11px] text-muted-foreground border-s border-border ps-2">افراکاو</span>
        </div>
        <div className="ms-auto flex items-center gap-4">
          {username && <span className="text-xs font-mono text-muted-foreground hidden sm:block" dir="ltr">{username}</span>}
          <button onClick={onSettings} title="تنظیمات حساب"
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-primary transition-colors">
            <SlidersHorizontal size={13} /> <span className="hidden sm:inline">تنظیمات</span>
          </button>
          <ThemeToggle />
          <button onClick={onLogout} className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-[#ff3b3b] transition-colors">
            <LogOut size={13} className="-scale-x-100" /> خروج
          </button>
        </div>
      </div>
    </nav>
  );
}

// ── Home screen (customer landing — search only, no upload) ─────────────────
function Home({ hosts, loading, scan, trend, attack, onSearch, username, onLogout, onSettings }: {
  hosts: HostRecord[]; loading: boolean; scan: ScanStatus | null; trend: EstateSnapshot[];
  attack: EstateAttack | null; onSearch: (q: string) => void;
  username?: string; onLogout: () => void; onSettings: () => void;
}) {
  const [q, setQ] = useState("");

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <BrandNav username={username} onLogout={onLogout} onSettings={onSettings} />

      {/* Hero */}
      <div className="flex-1 flex flex-col items-center px-4 py-10">
        <div className="w-full max-w-3xl">
          <h1 className="text-center text-3xl sm:text-4xl font-bold text-foreground mb-2 tracking-tight">
            جست‌وجو در <span className="text-primary">شبکهٔ شما</span>
          </h1>
          <p className="text-center text-sm text-muted-foreground mb-8 leading-relaxed">
            سطح حملهٔ سازمان خود را جست‌وجو کنید — هر IP، میزبان یا CVE را در شبکه‌هایی که افرانت برای شما پایش می‌کند بیابید و پورت‌های باز و آسیب‌پذیری‌ها را بررسی کنید.
          </p>

          {/* Search bar */}
          <form onSubmit={e => { e.preventDefault(); onSearch(q); }}
            className="flex items-center border border-border rounded overflow-hidden mb-6 bg-secondary focus-within:border-primary/40 transition-colors">
            <div className="px-4 text-muted-foreground"><Search size={16} /></div>
            <input
              autoFocus value={q} onChange={e => setQ(e.target.value)}
              dir="ltr"
              placeholder="192.168.1.10, hostname, CVE-2021-44228, port:445..."
              className="flex-1 py-3.5 bg-transparent text-sm font-mono text-foreground placeholder:text-muted-foreground focus:outline-none"
            />
            <button type="submit"
              className="flex items-center gap-2 px-5 py-3.5 border-s border-border text-xs text-muted-foreground hover:text-primary hover:bg-primary/10 transition-colors">
              <Search size={13} /> <span>جست‌وجو</span>
            </button>
          </form>

          {/* Example queries */}
          <div className="flex flex-wrap gap-2 justify-center mb-10" dir="ltr">
            {["has:exploit", "port:445", "vuln:CVE-2021-44228", "product:jenkins", "tag:rdp", "os:windows"].map(ex => (
              <button key={ex} onClick={() => onSearch(ex)}
                className="text-xs font-mono text-muted-foreground hover:text-primary border border-border hover:border-primary/30 rounded px-2.5 py-1 cursor-pointer transition-colors">{ex}</button>
            ))}
          </div>

          {/* Overview of this customer's own scans. It renders before any search
              is run, so the landing page answers "what do I have?" on its own. */}
          {loading ? (
            <div className="border border-border rounded bg-card py-10 flex justify-center text-muted-foreground">
              <Loader2 size={18} className="animate-spin" />
            </div>
          ) : hosts.length === 0 ? (
            /* No hosts can mean two different things, and the scan record is
               what separates them: a scan that ran and found nothing, or no
               scan yet. */
            <div className="space-y-3">
              <ScanBanner scan={scan} />
              <div className="border border-border rounded bg-card py-8 px-4 text-center text-xs text-muted-foreground">
                {scan
                  ? "اسکن انجام شده است، اما میزبانی در محدودهٔ اسکن پاسخ نداد. برای بازبینی محدوده با تیم افرانت تماس بگیرید."
                  : "هنوز اسکنی برای حساب شما بارگذاری نشده است. لطفاً با تیم افرانت تماس بگیرید."}
              </div>
            </div>
          ) : (
            <Dashboard hosts={hosts} onSearch={onSearch} scan={scan} trend={trend} attack={attack} />
          )}
        </div>
      </div>

      <footer className="border-t border-border py-4 px-4 text-center text-[12px] text-muted-foreground">
        افرانت ® افراکاو — مدیریت آسیب‌پذیری · مبتنی بر Nessus · <span dir="ltr">soc@afranet.io</span>
      </footer>
    </div>
  );
}

// ── Search results page (when query doesn't exactly match one IP) ──────────
function SearchResults({
  query, results, onSelect, onSearch, onHome, onBack,
}: {
  query: string; results: HostRecord[]; onSelect: (h: HostRecord) => void;
  onSearch: (q: string) => void; onHome: () => void; onBack: () => void;
}) {
  const [q, setQ] = useState(query);
  // The search box follows whatever query the screen is showing, so stepping
  // back through history never leaves a stale term in the field.
  useEffect(() => { setQ(query); }, [query]);

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Top bar */}
      <header className="sticky top-0 z-40 border-b border-border bg-card">
        <div className="max-w-6xl mx-auto px-4 py-2.5 flex items-center gap-3">
          <button onClick={onHome} title="بازگشت به داشبورد" className="flex items-center gap-1.5 flex-shrink-0">
            <Brand className="h-7" />
          </button>
          <button onClick={onBack} title="بازگشت به صفحهٔ قبل"
            className="flex items-center gap-1.5 flex-shrink-0 text-xs text-muted-foreground hover:text-primary border border-border hover:border-primary/30 rounded px-2 py-1.5 transition-colors">
            <ArrowRight size={12} /> <span className="hidden sm:block">بازگشت</span>
          </button>
          <button onClick={onHome} title="داشبورد"
            className="flex items-center gap-1.5 flex-shrink-0 text-xs text-muted-foreground hover:text-primary border border-border hover:border-primary/30 rounded px-2 py-1.5 transition-colors">
            <LayoutDashboard size={12} /> <span className="hidden lg:block">داشبورد</span>
          </button>
          <form className="flex-1 flex items-center bg-secondary border border-border rounded overflow-hidden focus-within:border-primary/40 transition-colors max-w-2xl" onSubmit={e => { e.preventDefault(); onSearch(q); }}>
            <span className="px-3 text-muted-foreground flex-shrink-0"><Search size={13} /></span>
            <input
              value={q} onChange={e => setQ(e.target.value)}
              dir="ltr"
              className="flex-1 py-2 bg-transparent text-sm font-mono text-foreground placeholder:text-muted-foreground focus:outline-none"
            />
            {q && <button type="button" onClick={() => setQ("")} className="px-3 text-muted-foreground hover:text-foreground"><X size={12} /></button>}
          </form>
          <span className="text-xs text-muted-foreground hidden md:block flex-shrink-0">
            {faNum(results.length)} نتیجه
          </span>
          <ThemeToggle />
        </div>
      </header>

      <div className="flex-1 flex max-w-6xl w-full mx-auto px-4 py-5 gap-6">
        {/* Facets */}
        <aside className="hidden md:block w-44 flex-shrink-0 space-y-6">
          <div>
            <p className="text-[11px] text-muted-foreground mb-2">پورت‌های پرتکرار</p>
            {Array.from(new Set(results.flatMap(h => h.ports.map(p => p.port)))).slice(0, 8).map(port => (
              <button key={port} onClick={() => onSearch(`port:${port}`)} className="flex items-center justify-between w-full px-2 py-1 text-xs font-mono text-muted-foreground hover:text-primary hover:bg-secondary rounded transition-colors">
                <span dir="ltr">{port}</span>
                <span className="text-[11px]">{faNum(results.filter(h => h.ports.some(p => p.port === port)).length)}</span>
              </button>
            ))}
          </div>
          <div>
            <p className="text-[11px] text-muted-foreground mb-2">سیستم‌عامل</p>
            {Array.from(new Set(results.map(h => h.os.split(" ").slice(0, 2).join(" ")))).map(os => (
              <button key={os} onClick={() => onSearch(os)} className="flex items-center justify-between w-full px-2 py-1 text-xs font-mono text-muted-foreground hover:text-primary hover:bg-secondary rounded transition-colors text-start">
                <span className="truncate" dir="ltr">{os}</span>
                <span className="text-[11px] flex-shrink-0 ms-1">{faNum(results.filter(h => h.os.startsWith(os)).length)}</span>
              </button>
            ))}
          </div>
          <div>
            <p className="text-[11px] text-muted-foreground mb-2">برچسب‌ها</p>
            {Array.from(new Set(results.flatMap(h => h.tags))).slice(0, 10).map(tag => (
              <button key={tag} onClick={() => onSearch(`tag:${tag}`)} className="flex items-center justify-between w-full px-2 py-1 text-xs font-mono text-muted-foreground hover:text-primary hover:bg-secondary rounded transition-colors">
                <span dir="ltr">{tag}</span>
                <span className="text-[11px]">{faNum(results.filter(h => h.tags.includes(tag)).length)}</span>
              </button>
            ))}
          </div>
        </aside>

        {/* Results list */}
        <div className="flex-1 min-w-0 space-y-3">
          {results.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center px-4">
              <Search size={36} className="text-muted-foreground mb-4 opacity-20" />
              <p className="text-sm text-foreground mb-1.5">
                نتیجه‌ای برای «<span dir="ltr" className="font-mono">{query}</span>» یافت نشد
              </p>
              <p className="text-xs text-muted-foreground leading-relaxed max-w-md">
                {looksLikeIp(query)
                  ? "این نشانی جزو میزبان‌های اسکن‌شدهٔ شما نیست. اگر باید در محدودهٔ پایش باشد، با تیم افرانت تماس بگیرید."
                  : "هیچ میزبان، پورت، سرویس یا CVE مطابق این عبارت در اسکن‌های شما ثبت نشده است."}
              </p>
              <div className="flex items-center gap-4 mt-4">
                <button onClick={onBack} className="text-xs text-primary hover:underline">بازگشت</button>
                <button onClick={onHome} className="text-xs text-muted-foreground hover:text-primary">داشبورد</button>
              </div>
            </div>
          ) : (
            results.map(h => {
              const critCount = h.vulns.filter(v => v.severity === "Critical").length;
              const highCount = h.vulns.filter(v => v.severity === "High").length;
              return (
                <div
                  key={h.ip}
                  onClick={() => onSelect(h)}
                  className="border border-border rounded bg-card hover:border-primary/40 transition-colors cursor-pointer group p-4"
                >
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div>
                      <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                        <span className="font-mono font-bold text-primary text-base group-hover:underline" dir="ltr">{h.ip}</span>
                        {critCount > 0 && <span className="text-[10px] font-bold px-1.5 py-0.5 bg-[#ff3b3b]/10 border border-[#ff3b3b]/25 text-[#ff3b3b] rounded">{faNum(critCount)} بحرانی</span>}
                        {h.vulns.some(v => v.exploitAvailable) && (
                          <span className="flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 bg-[#ff3b3b]/10 border border-[#ff3b3b]/25 text-[#ff3b3b] rounded">
                            <Zap size={8} /> اکسپلویت
                          </span>
                        )}
                      </div>
                      <div className="flex flex-wrap gap-2 text-[12px] text-muted-foreground font-mono" dir="ltr">
                        {h.hostnames.map(n => <span key={n}>{n}</span>)}
                      </div>
                    </div>
                    <div className="text-end text-[12px] text-muted-foreground flex-shrink-0">
                      <p dir="ltr" className="font-mono">{subnetLabel(h.ip)}</p>
                      <p>{timeAgo(h.lastScan)}</p>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-x-4 gap-y-0.5 mb-3 text-[12px] text-muted-foreground">
                    <span className="flex items-center gap-1"><Building size={10} /><span dir="ltr">{h.org}</span></span>
                    <span className="flex items-center gap-1"><Cpu size={10} /><span dir="ltr">{h.os}</span></span>
                    {/* A bare "۰ یافته" reads like a missing number rather than
                        a clean result, so a host with nothing on it says so. */}
                    {h.vulns.length === 0 ? (
                      <span className="flex items-center gap-1 text-[#2ea043]">
                        <ShieldCheck size={10} /> آسیب‌پذیری یافت نشد
                      </span>
                    ) : (
                      <span className="flex items-center gap-1"><Activity size={10} />{faNum(h.vulns.length)} یافته</span>
                    )}
                  </div>

                  <div className="flex flex-wrap gap-1.5 mb-3">
                    {h.ports.map(p => (
                      <span key={p.port} dir="ltr" className={`text-[11px] font-mono border border-current/20 bg-current/5 rounded px-1.5 py-0.5 ${svcCls(p.service)}`}>
                        <span className="font-bold">{p.port}</span><span className="opacity-60">/{p.service}</span>
                      </span>
                    ))}
                  </div>

                  {h.vulns.filter(v => v.cve !== "N/A").length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {h.vulns.filter(v => v.cve !== "N/A").slice(0, 4).map(v => (
                        <span key={v.cve} dir="ltr" className="text-[10px] font-mono px-1.5 py-0.5 bg-[#ff3b3b]/8 border border-[#ff3b3b]/20 text-[#ff3b3b]/80 rounded">{v.cve}</span>
                      ))}
                      {h.vulns.filter(v => v.cve !== "N/A").length > 4 && (
                        <span className="text-[10px] px-1.5 py-0.5 bg-secondary border border-border text-muted-foreground rounded">{faNum(h.vulns.filter(v => v.cve !== "N/A").length - 4)} مورد دیگر</span>
                      )}
                      <span className="ms-auto text-[11px] font-mono text-muted-foreground self-center" dir="ltr">
                        {critCount}C · {highCount}H · {h.vulns.filter(v => v.severity === "Medium").length}M
                      </span>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}

// ── Host detail page (Shodan-style) ────────────────────────────────────────
function HostPage({ host, onBack, backLabel, onHome, onSearch }: {
  host: HostRecord; onBack: () => void; backLabel: string;
  onHome: () => void; onSearch: (q: string) => void;
}) {
  const [openPort, setOpenPort] = useState<number | null>(null);
  const [vulnFilter, setVulnFilter] = useState<Sev | "All" | "Exploit">("All");
  const [q, setQ] = useState(host.ip);

  const filteredVulns =
    vulnFilter === "All" ? host.vulns
    : vulnFilter === "Exploit" ? host.vulns.filter(v => v.exploitAvailable)
    : host.vulns.filter(v => v.severity === vulnFilter);
  const exploitCount = host.vulns.filter(v => v.exploitAvailable).length;
  const sevCounts = (["Critical", "High", "Medium", "Low", "Info"] as Sev[]).map(s => ({ s, count: host.vulns.filter(v => v.severity === s).length }));
  const hasVulns = host.vulns.length > 0;

  // Moving between hosts (or stepping back through history) reuses this
  // component, so the search box and the filter have to follow the new host
  // rather than keeping the previous one's state.
  useEffect(() => { setQ(host.ip); setVulnFilter("All"); setOpenPort(null); }, [host.ip]);

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Top nav */}
      <header className="sticky top-0 z-40 border-b border-border bg-card">
        <div className="max-w-6xl mx-auto px-4 py-2.5 flex items-center gap-3">
          <button onClick={onHome} title="بازگشت به داشبورد" className="flex items-center gap-1.5 flex-shrink-0">
            <Brand className="h-7" />
          </button>
          <button onClick={onBack}
            className="flex items-center gap-1.5 flex-shrink-0 text-xs text-muted-foreground hover:text-primary border border-border hover:border-primary/30 rounded px-2 py-1.5 transition-colors">
            <ArrowRight size={12} /> <span className="hidden sm:block">{backLabel}</span>
          </button>
          <form onSubmit={e => { e.preventDefault(); onSearch(q); }} className="flex-1 flex items-center bg-secondary border border-border rounded overflow-hidden focus-within:border-primary/40 transition-colors max-w-2xl">
            <span className="px-3 text-muted-foreground flex-shrink-0"><Search size={13} /></span>
            <input value={q} onChange={e => setQ(e.target.value)} dir="ltr" className="flex-1 py-2 bg-transparent text-sm font-mono text-foreground focus:outline-none" />
          </form>
          <ThemeToggle />
        </div>
      </header>

      <div className="max-w-6xl mx-auto w-full px-4 py-6 flex gap-6">
        {/* ── Sidebar ── */}
        <aside className="hidden md:flex flex-col gap-5 w-52 xl:w-60 flex-shrink-0">
          {/* General info box */}
          <div className="bg-card border border-border rounded p-4 space-y-3">
            <p className="text-[11px] text-muted-foreground">اطلاعات کلی</p>
            {[
              { label: "نشانی IP", value: host.ip, cls: "text-primary font-mono", ltr: true },
              { label: "نام میزبان‌ها", value: host.hostnames.join("\n"), cls: "text-foreground font-mono text-[12px]", ltr: true },
              { label: "دامنه‌ها", value: host.domains.join(", "), cls: "text-foreground font-mono text-[12px]", ltr: true },
              // Nessus carries no location data, so the panel shows what the scan
              // really knows: which subnet the host sits in.
              { label: "زیرشبکه", value: subnetLabel(host.ip), cls: "text-foreground font-mono", ltr: true },
              { label: "سازمان", value: host.org, cls: "text-foreground", ltr: true },
              { label: "سیستم‌عامل", value: host.os, cls: "text-foreground", ltr: true },
              { label: "آخرین اسکن", value: timeAgo(host.lastScan), cls: "text-foreground", ltr: false },
            ].map(({ label, value, cls, ltr }) => (
              <div key={label}>
                <p className="text-[10px] text-muted-foreground">{label}</p>
                <p dir={ltr ? "ltr" : undefined} className={`text-xs mt-0.5 break-words whitespace-pre-line leading-snug ${ltr ? "text-end" : ""} ${cls}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* Tags */}
          {host.tags.length > 0 && (
            <div className="bg-card border border-border rounded p-4">
              <p className="text-[11px] text-muted-foreground mb-2">برچسب‌ها</p>
              <div className="flex flex-wrap gap-1.5">
                {host.tags.map(t => (
                  <button key={t} onClick={() => onSearch(`tag:${t}`)} className="text-[11px] font-mono px-2 py-0.5 border border-border rounded text-muted-foreground hover:text-primary hover:border-primary/30 transition-colors flex items-center gap-1">
                    <Tag size={8} /><span dir="ltr">{t}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Vuln summary */}
          <div className="bg-card border border-border rounded p-4">
            <p className="text-[11px] text-muted-foreground mb-3">آسیب‌پذیری‌ها</p>
            {!hasVulns && (
              <p className="flex items-start gap-1.5 text-[12px] text-[#2ea043] leading-relaxed">
                <ShieldCheck size={12} className="flex-shrink-0 mt-0.5" />
                موردی یافت نشد
              </p>
            )}
            <div className="space-y-1.5">
              {sevCounts.map(({ s, count }) => count > 0 && (
                <button
                  key={s}
                  onClick={() => setVulnFilter(f => f === s ? "All" : s)}
                  className={`flex items-center justify-between w-full px-2 py-1 rounded transition-colors text-xs
                    ${vulnFilter === s ? `${SEV[s].bg} ${SEV[s].color}` : "text-muted-foreground hover:bg-secondary"}`}
                >
                  <span>{SEV_FA[s]}</span>
                  <span className={vulnFilter === s ? SEV[s].color : ""}>{faNum(count)}</span>
                </button>
              ))}
            </div>
          </div>
        </aside>

        {/* ── Main content ── */}
        <main className="flex-1 min-w-0 space-y-5">
          {/* IP heading */}
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="font-mono font-bold text-2xl text-primary" dir="ltr">{host.ip}</h1>
            {host.vulns.filter(v => v.severity === "Critical").length > 0 && (
              <span className="text-xs font-bold px-2 py-0.5 bg-[#ff3b3b]/10 border border-[#ff3b3b]/30 text-[#ff3b3b] rounded">
                {faNum(host.vulns.filter(v => v.severity === "Critical").length)} آسیب‌پذیری بحرانی
              </span>
            )}
            {!hasVulns && (
              <span className="flex items-center gap-1 text-xs font-bold px-2 py-0.5 bg-[#2ea043]/10 border border-[#2ea043]/30 text-[#2ea043] rounded">
                <ShieldCheck size={11} /> بدون آسیب‌پذیری
              </span>
            )}
          </div>

          {/* ── Open Ports ── */}
          <section className="bg-card border border-border rounded overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-secondary/20 flex items-center gap-2">
              <Wifi size={13} className="text-primary" />
              <span className="text-xs font-semibold text-foreground">
                پورت‌های باز — {faNum(host.ports.length)} سرویس شناسایی شد
              </span>
            </div>

            {host.ports.map(p => {
              const isOpen = openPort === p.port;
              return (
                <div key={p.port} className="border-b border-border last:border-0">
                  {/* Port row */}
                  <div
                    className="flex items-center gap-4 px-4 py-3 hover:bg-secondary/20 cursor-pointer transition-colors group"
                    onClick={() => setOpenPort(isOpen ? null : p.port)}
                  >
                    <div className="flex items-center gap-2 flex-shrink-0 w-24" dir="ltr">
                      <span className="font-mono font-bold text-primary text-sm">{p.port}</span>
                      <span className="text-[11px] font-mono text-muted-foreground">{p.proto.toUpperCase()}</span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap" dir="ltr">
                        <span className={`text-xs font-mono font-semibold ${svcCls(p.service)}`}>{p.service}</span>
                        <span className="text-xs text-muted-foreground font-mono">{p.product}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0 text-muted-foreground">
                      <span className="text-[11px] group-hover:text-primary transition-colors">{isOpen ? "بستن" : "نمایش بنر"}</span>
                      {isOpen ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                    </div>
                  </div>
                  {/* Banner */}
                  {isOpen && (
                    <div className="px-4 pb-4" dir="ltr" style={{ background: "var(--terminal-bg)" }}>
                      <pre className="text-[12px] font-mono text-muted-foreground whitespace-pre-wrap leading-relaxed border border-border/50 rounded p-3 overflow-x-auto text-left">
                        {p.banner}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })}
          </section>

          {/* ── Vulnerabilities ──
              A host with nothing on it gets a statement, not an empty list:
              "no findings" and "not scanned" look identical otherwise. */}
          {!hasVulns ? (
            <section className="bg-card border border-[#2ea043]/30 rounded overflow-hidden">
              <div className="px-4 py-3 border-b border-[#2ea043]/20 bg-[#2ea043]/5 flex items-center gap-2">
                <ShieldCheck size={13} className="text-[#2ea043]" />
                <span className="text-xs font-semibold text-foreground">آسیب‌پذیری‌ها</span>
              </div>
              <div className="px-4 py-9 text-center">
                <ShieldCheck size={30} className="text-[#2ea043] mx-auto mb-3" />
                <p className="text-sm text-foreground mb-2">
                  هیچ آسیب‌پذیری‌ای روی این نشانی یافت نشد
                </p>
                <p className="text-[12px] text-muted-foreground leading-relaxed max-w-lg mx-auto">
                  این میزبان {timeAgo(host.lastScan)} اسکن شد و {faNum(host.ports.length)} سرویس باز روی آن
                  شناسایی شد، اما هیچ یافتهٔ آسیب‌پذیری‌ای ثبت نشده است.
                </p>
              </div>
            </section>
          ) : (
          <section className="bg-card border border-border rounded overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-secondary/20 flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-2">
                <AlertTriangle size={13} className="text-[#ff3b3b]" />
                <span className="text-xs font-semibold text-foreground">
                  آسیب‌پذیری‌ها — {faNum(host.vulns.length)} یافته
                </span>
              </div>
              <div className="flex items-center gap-1 flex-wrap">
                {(["All", "Critical", "High", "Medium", "Low"] as (Sev | "All")[]).map(s => (
                  <button
                    key={s}
                    onClick={() => setVulnFilter(s)}
                    className={`text-[11px] px-2 py-0.5 rounded border transition-colors
                      ${vulnFilter === s
                        ? s === "All" ? "bg-primary/10 border-primary/30 text-primary" : `${SEV[s as Sev].bg} ${SEV[s as Sev].border} ${SEV[s as Sev].color}`
                        : "border-border text-muted-foreground hover:text-foreground hover:bg-secondary"
                      }`}
                  >
                    {s === "All" ? "همه" : SEV_FA[s as Sev]}
                  </button>
                ))}
                {exploitCount > 0 && (
                  <button
                    onClick={() => setVulnFilter("Exploit")}
                    className={`flex items-center gap-1 text-[11px] px-2 py-0.5 rounded border transition-colors
                      ${vulnFilter === "Exploit"
                        ? "bg-[#ff3b3b]/10 border-[#ff3b3b]/30 text-[#ff3b3b]"
                        : "border-border text-muted-foreground hover:text-foreground hover:bg-secondary"
                      }`}
                  >
                    <Zap size={9} /> اکسپلویت‌پذیر {faNum(exploitCount)}
                  </button>
                )}
              </div>
            </div>

            <div className="divide-y divide-border">
              {filteredVulns.map(v => (
                <div key={v.pluginId} className="px-4 py-4 hover:bg-secondary/10 transition-colors">
                  <div className="flex items-start gap-3">
                    <SevBadge s={v.severity} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-foreground leading-snug mb-1.5" dir="ltr" style={{ textAlign: "start" }}>{v.name}</p>

                      <div className="flex flex-wrap items-center gap-3 mb-2.5">
                        {v.cve !== "N/A" && (
                          <span className="text-[12px] font-mono text-primary" dir="ltr">{v.cve}</span>
                        )}
                        <span className="text-[12px] text-muted-foreground">پلاگین <span className="font-mono" dir="ltr">#{v.pluginId}</span></span>
                        <span className="text-[12px] font-mono text-muted-foreground" dir="ltr">{v.family}</span>
                        <span dir="ltr" className={`text-[12px] font-mono font-bold ${v.cvss >= 9 ? "text-[#ff3b3b]" : v.cvss >= 7 ? "text-[#ff8c00]" : v.cvss >= 4 ? "text-[#f5c518]" : "text-[#2ea043]"}`}>
                          CVSS {v.cvss.toFixed(1)}
                        </span>
                        <ExploitBadges vuln={v} />
                      </div>

                      <p className="text-[13px] text-muted-foreground leading-relaxed mb-2.5" dir="ltr" style={{ textAlign: "start" }}>{v.description}</p>

                      <div className="flex items-start gap-2 p-2.5 rounded bg-primary/5 border border-primary/15">
                        <CheckCircle size={11} className="text-primary mt-0.5 flex-shrink-0" />
                        <div>
                          <p className="text-[10px] text-primary mb-0.5">راهکار</p>
                          <p className="text-[12px] text-foreground/80 leading-relaxed" dir="ltr" style={{ textAlign: "start" }}>{v.solution}</p>
                        </div>
                      </div>

                      {safeHref(v.seeAlso) && (
                        <a href={safeHref(v.seeAlso)} target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()} className="mt-2 inline-flex items-center gap-1 text-[11px] text-primary hover:underline">
                          <ExternalLink size={9} /> اطلاعات بیشتر
                        </a>
                      )}
                    </div>
                  </div>
                </div>
              ))}
              {filteredVulns.length === 0 && (
                <div className="px-4 py-8 text-center text-xs text-muted-foreground">
                  {vulnFilter === "All" ? "آسیب‌پذیری‌ای یافت نشد"
                    : vulnFilter === "Exploit" ? "یافته‌ای با اکسپلویت منتشرشده روی این میزبان وجود ندارد"
                    : `آسیب‌پذیری با شدت «${SEV_FA[vulnFilter]}» روی این میزبان وجود ندارد`}
                </div>
              )}
            </div>
          </section>
          )}

          {/* What an attacker could do with the findings above. */}
          <AttackPanel host={host.ip} />
        </main>
      </div>

      <footer className="border-t border-border py-4 px-4 text-center text-[12px] text-muted-foreground">
        افرانت ® افراکاو · <span dir="ltr">soc@afranet.io</span>
      </footer>
    </div>
  );
}

// ── Customer app (search dashboard, scoped to the logged-in tenant) ─────────

/**
 * Which screen the customer is on. The entire view is derived from this one
 * value, and every navigation pushes it onto the browser's history stack — so
 * the browser's back button and a phone's back gesture step back through the
 * panel instead of leaving it.
 */
type View =
  | { screen: "home" }
  | { screen: "results"; query: string }
  | { screen: "host"; ip: string; from: "home" | "results" }
  | { screen: "settings" };

/**
 * Shodan-style filtering over the hosts this account already holds. Pure, so a
 * screen restored from history can recompute its own results instead of
 * needing them stored alongside it.
 */
function filterHosts(hosts: HostRecord[], q: string): HostRecord[] {
  const lower = q.toLowerCase().trim();
  if (!lower) return hosts;

  return hosts.filter(h => {
    if (lower.startsWith("port:")) {
      const port = parseInt(lower.split(":")[1]);
      return h.ports.some(p => p.port === port);
    }
    if (lower.startsWith("tag:")) {
      return h.tags.includes(lower.split(":")[1]);
    }
    if (lower.startsWith("vuln:") || lower.startsWith("cve:")) {
      const cve = lower.split(":")[1].toUpperCase();
      return h.vulns.some(v => v.cve.toUpperCase().includes(cve));
    }
    // severity:critical — what the dashboard chart narrows to when a bar is
    // clicked.
    if (lower.startsWith("family:")) {
      const want = lower.slice(7);
      return h.vulns.some(v => v.family.toLowerCase().includes(want));
    }
    if (lower.startsWith("severity:") || lower.startsWith("sev:")) {
      const want = lower.split(":")[1];
      return h.vulns.some(v => v.severity.toLowerCase() === want);
    }
    if (lower.startsWith("product:")) {
      const prod = lower.split(":")[1];
      return h.ports.some(p => p.product.toLowerCase().includes(prod));
    }
    if (lower.startsWith("os:")) {
      return h.os.toLowerCase().includes(lower.slice(3));
    }
    // subnet:10.20.30 matches 10.20.30.* and nothing wider.
    if (lower.startsWith("subnet:") || lower.startsWith("net:")) {
      const prefix = lower.split(":")[1].replace(/\.$/, "");
      return h.ip.startsWith(prefix + ".");
    }
    if (lower.startsWith("has:") || lower.startsWith("exploit:")) {
      const [key, val] = lower.split(":");
      if (key === "exploit") {
        const want = val === "true" || val === "yes" || val === "1";
        return h.vulns.some(v => v.exploitAvailable) === want;
      }
      if (val === "exploit") return h.vulns.some(v => v.exploitAvailable);
      if (val === "malware") return h.vulns.some(v => v.exploitedByMalware);
      if (val === "critical") return h.vulns.some(v => v.severity === "Critical");
      return false;
    }
    if (lower === "*") return true;
    return (
      h.ip.includes(lower) ||
      h.hostnames.some(n => n.toLowerCase().includes(lower)) ||
      h.domains.some(d => d.includes(lower)) ||
      h.os.toLowerCase().includes(lower) ||
      h.org.toLowerCase().includes(lower) ||
      h.tags.some(t => t.includes(lower)) ||
      h.ports.some(p => String(p.port) === lower || p.service.includes(lower) || p.product.toLowerCase().includes(lower)) ||
      h.vulns.some(v => v.cve.toLowerCase().includes(lower) || v.name.toLowerCase().includes(lower))
    );
  });
}

function FullScreen({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center text-muted-foreground">
      {children}
    </div>
  );
}

function CustomerApp() {
  const { user, logout } = useAuth();
  const [view, setView] = useState<View>({ screen: "home" });
  // `hosts` holds ONLY this customer's hosts — the backend scopes the response
  // by the authenticated user, so a tenant can never see another's IPs.
  const [hosts, setHosts] = useState<HostRecord[]>([]);
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [trend, setTrend] = useState<EstateSnapshot[]>([]);
  const [attack, setAttack] = useState<EstateAttack | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    fetchHosts()
      .then(remote => { if (!cancelled) setHosts(remote as HostRecord[]); })
      .catch(() => { /* empty state */ })
      .finally(() => { if (!cancelled) setLoading(false); });

    // The scan record is separate evidence from the findings: it says a scan
    // ran, which is the one thing an empty findings list cannot say for itself.
    fetchScans()
      .then(list => {
        if (cancelled || list.length === 0) return;
        setScan({ at: list[0].uploadedAt, count: list.length });
      })
      .catch(() => { /* the panel just omits the scan line */ });

    // One point per scan, describing the estate right after it. Starts
    // accumulating from the first upload made after this feature shipped.
    fetchTrend()
      .then(points => { if (!cancelled) setTrend(points); })
      .catch(() => { /* the trend panel explains itself when empty */ });

    // ATT&CK is derived server-side from the same findings, so it is a
    // separate request rather than something the dashboard recomputes.
    fetchAttack()
      .then(res => { if (!cancelled) setAttack(res); })
      .catch(() => { /* the panel is simply omitted */ });

    return () => { cancelled = true; };
  }, []);

  // Back and forward move between the screens the customer actually visited.
  useEffect(() => {
    window.history.replaceState({ afrakav: { screen: "home" } as View }, "");
    const onPop = (e: PopStateEvent) => {
      const restored = (e.state as { afrakav?: View } | null)?.afrakav;
      setView(restored ?? { screen: "home" });
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const go = (next: View) => {
    setView(next);
    window.history.pushState({ afrakav: next }, "");
  };
  // In-page back and the browser's own back do the same thing, so the two can
  // never disagree about where "previous" is.
  const back = () => window.history.back();
  const home = () => go({ screen: "home" });

  const results = useMemo(
    () => (view.screen === "results" ? filterHosts(hosts, view.query) : []),
    [hosts, view],
  );

  const doSearch = (q: string) => {
    const query = q.trim();
    if (!query) { home(); return; }

    // An exact IP opens that host directly rather than a one-row result list.
    const exact = hosts.find(h => h.ip === query.toLowerCase());
    if (exact) {
      go({ screen: "host", ip: exact.ip, from: view.screen === "results" ? "results" : "home" });
      return;
    }
    go({ screen: "results", query });
  };

  const selectHost = (h: HostRecord) => go({ screen: "host", ip: h.ip, from: "results" });

  if (view.screen === "settings") return <Settings onBack={back} />;

  if (view.screen === "results") return (
    <SearchResults
      query={view.query}
      results={results}
      onSelect={selectHost}
      onSearch={doSearch}
      onHome={home}
      onBack={back}
    />
  );

  if (view.screen === "host") {
    const host = hosts.find(h => h.ip === view.ip);
    if (host) return (
      <HostPage
        host={host}
        onBack={back}
        backLabel={view.from === "results" ? "بازگشت به نتایج" : "بازگشت به داشبورد"}
        onHome={home}
        onSearch={doSearch}
      />
    );
    // Stepping back into a host before the list has loaded.
    if (loading) return <FullScreen><Loader2 size={22} className="animate-spin" /></FullScreen>;
    // The address is no longer in this account's scans — say so rather than
    // showing a blank screen.
    return (
      <SearchResults
        query={view.ip} results={[]} onSelect={selectHost}
        onSearch={doSearch} onHome={home} onBack={back}
      />
    );
  }

  return (
    <Home hosts={hosts} loading={loading} scan={scan} trend={trend} attack={attack} onSearch={doSearch}
      username={user?.username} onLogout={logout} onSettings={() => go({ screen: "settings" })} />
  );
}

// ── Root: auth gate → Login / Admin / Customer ──────────────────────────────
function Root() {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center text-muted-foreground">
        <Loader2 size={22} className="animate-spin" />
      </div>
    );
  }
  if (!user) return <Login />;
  if (user.role === "admin") return <Admin />;
  return <CustomerApp />;
}

export default function App() {
  return (
    <AuthProvider>
      <Root />
    </AuthProvider>
  );
}
