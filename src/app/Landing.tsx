import { useEffect, useState } from "react";
import {
  Search, ShieldCheck, Activity, Crosshair, TrendingDown, Lock,
  ArrowLeft, Loader2, EyeOff, ScrollText, Building2, Radar,
} from "lucide-react";
import { Showcase, ShowcaseHost, fetchShowcase } from "./api";
import { faNum } from "./format";
import { SEV_COLOR, SEV_FA } from "./components/severity";
import Brand from "./components/Brand";
import ThemeToggle from "./components/ThemeToggle";

/**
 * The public front door.
 *
 * The page is built around one idea: a visitor believes "we can see your
 * attack surface" far more readily when shown a real scan than when told. So
 * the sample is the hero — first as a live-looking readout beside the
 * headline, then in full underneath.
 *
 * What makes that safe is that the backend redacted the scan when it was
 * published, not here: this component renders whatever it is given and has no
 * access to an unredacted host.
 */
export default function Landing({ onSignIn, onRequestAccess }: {
  onSignIn: () => void;
  onRequestAccess: () => void;
}) {
  const [showcase, setShowcase] = useState<Showcase | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetchShowcase()
      .then(res => { if (!cancelled && res.published && res.showcase) setShowcase(res.showcase); })
      .catch(() => { /* the sample sections simply do not render */ })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  // Section numbers shift when there is no published sample, so the sequence
  // never shows a gap.
  const n = (i: number) => ["۰۱", "۰۲", "۰۳", "۰۴"][showcase ? i : i - 1];

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <nav className="border-b border-border bg-background/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-5 py-3 flex items-center gap-4">
          <Brand className="h-7" />
          <span className="text-[11px] text-muted-foreground border-s border-border ps-3 hidden sm:block">
            مدیریت آسیب‌پذیری
          </span>
          <div className="ms-auto flex items-center gap-3">
            <ThemeToggle />
            <button onClick={onSignIn}
              className="flex items-center gap-1.5 text-xs text-foreground border border-border hover:border-primary/50
                         hover:text-primary rounded px-3.5 py-1.5 transition-colors">
              <Lock size={12} /> ورود
            </button>
          </div>
        </div>
      </nav>

      {/* ── hero ── */}
      <header className="relative overflow-hidden hero-glow">
        <div className="absolute inset-0 grid-backdrop" aria-hidden="true" />

        <div className="relative max-w-6xl mx-auto w-full px-5 pt-16 pb-16 sm:pt-24 sm:pb-24
                        grid lg:grid-cols-[1.5fr_1fr] gap-12 lg:gap-14 items-center">
          <div>
            <p className="inline-flex items-center gap-2 text-[11px] text-primary border border-primary/25
                          bg-primary/5 rounded-full px-3 py-1 mb-7">
              <span className="live-dot w-1.5 h-1.5 rounded-full bg-primary" />
              سرویس مدیریت آسیب‌پذیری افرانت
            </p>

            {/* Sized so each authored line fits on one rendered line — an
                orphaned full stop is the tell of a headline that was set
                bigger than its column. */}
            <h1 className="text-[1.95rem] sm:text-[2.5rem] lg:text-[2.6rem] font-bold text-foreground
                           leading-[1.35] tracking-tight text-balance">
              شبکهٔ خود را از بیرون ببینید،
              <br />
              <span className="text-primary">پیش از آنکه دیگری ببیند.</span>
            </h1>

            <p className="mt-7 text-sm sm:text-[15px] text-muted-foreground leading-loose max-w-xl">
              افراکاو زیرساخت سازمان شما را دوره‌ای اسکن می‌کند، پورت‌های باز و سرویس‌های در معرض را
              فهرست می‌کند، آسیب‌پذیری‌ها را بر اساس قابلیت بهره‌برداری اولویت‌بندی می‌کند، و نشان
              می‌دهد وضعیت شما نسبت به اسکن قبل بهتر شده یا بدتر.
            </p>

            <div className="mt-9 flex flex-wrap items-center gap-3">
              <button onClick={onRequestAccess}
                className="flex items-center gap-2 text-sm bg-primary text-primary-foreground rounded
                           px-6 py-3 hover:opacity-90 transition-opacity">
                درخواست دسترسی <ArrowLeft size={14} />
              </button>
              <button onClick={onSignIn}
                className="text-sm text-muted-foreground hover:text-primary border border-border
                           hover:border-primary/30 rounded px-6 py-3 transition-colors">
                ورود مشتریان
              </button>
            </div>
          </div>

          {/* The product, shown rather than described. */}
          <ScanReadout showcase={showcase} loading={loading} />
        </div>
      </header>

      {showcase && <StatsBand showcase={showcase} />}

      {showcase && (
        <Section index="۰۱" title="نمونه‌ای از یک اسکن واقعی"
                 lede="این نتایج از اسکن واقعی یک شبکه گرفته شده است.">
          <ShowcaseList showcase={showcase} />
        </Section>
      )}

      <Section index={n(1)} title="چطور کار می‌کند"
               lede="سرویس مدیریت‌شده است؛ لازم نیست چیزی نصب کنید یا ابزاری بخرید."
               tinted>
        <ol className="grid sm:grid-cols-3 gap-px bg-border border border-border rounded overflow-hidden">
          {[
            { n: "۱", title: "اسکن دوره‌ای", body: "کارشناسان افرانت محدودهٔ توافق‌شده را در دوره‌های شش‌ماهه تا هفتگی اسکن می‌کنند. چیزی روی سرورهای شما نصب نمی‌شود." },
            { n: "۲", title: "تحلیل و اولویت‌بندی", body: "یافته‌ها بررسی و خطاهای مثبت کاذب کنار گذاشته می‌شوند. آنچه اکسپلویت منتشرشده دارد، بالاتر از نمرهٔ CVSS می‌نشیند." },
            { n: "۳", title: "پایش روند", body: "هر اسکن به وضعیت کل شبکه اضافه می‌شود تا ببینید چه چیزی رفع شده و چه چیزی تازه پیدا شده است." },
          ].map(step => (
            <li key={step.n} className="bg-card p-6 flex flex-col gap-3">
              <span className="w-7 h-7 rounded-full border border-primary/30 bg-primary/5 text-primary
                               font-mono text-[12px] flex items-center justify-center">
                {step.n}
              </span>
              <h3 className="text-sm font-semibold text-foreground">{step.title}</h3>
              <p className="text-[13px] text-muted-foreground leading-relaxed">{step.body}</p>
            </li>
          ))}
        </ol>
      </Section>

      <Section index={n(2)} title="آنچه در پنل می‌بینید">
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-px bg-border border border-border rounded overflow-hidden">
          {[
            { icon: Search, title: "جست‌وجوی شبکه", body: "هر IP، نام میزبان، پورت، سرویس یا CVE را در دارایی‌های خود پیدا کنید." },
            { icon: Activity, title: "اولویت‌بندی بر پایهٔ اکسپلویت", body: "یافته‌هایی که اکسپلویت عمومی دارند جدا می‌شوند؛ اینها اول رفع می‌شوند." },
            { icon: Crosshair, title: "نگاشت MITRE ATT&CK", body: "هر ضعف به تکنیک‌هایی که مهاجم می‌تواند اجرا کند نگاشت می‌شود، با ذکر منبع نگاشت." },
            { icon: TrendingDown, title: "روند بهبود", body: "نمودار یافته‌ها در طول زمان؛ پاسخ روشن به «آیا بهتر شدیم؟»." },
            { icon: ScrollText, title: "گزارش رویدادها", body: "هر ورود، خروج و اقدام مدیریتی در یک دفتر تغییرناپذیر ثبت می‌شود." },
            { icon: Building2, title: "جداسازی کامل", body: "داده‌های هر سازمان در سمت سرور جدا می‌شود؛ دیدن دادهٔ سازمان دیگر ممکن نیست." },
          ].map(f => (
            <div key={f.title} className="bg-card p-6 flex flex-col gap-3 hover:bg-secondary/20 transition-colors">
              <span className="w-8 h-8 rounded border border-primary/20 bg-primary/5 flex items-center justify-center">
                <f.icon size={15} className="text-primary" />
              </span>
              <h3 className="text-sm font-semibold text-foreground">{f.title}</h3>
              <p className="text-[13px] text-muted-foreground leading-relaxed">{f.body}</p>
            </div>
          ))}
        </div>
      </Section>

      <Section index={n(3)} title="دادهٔ شما چطور نگهداری می‌شود"
               lede="نتیجهٔ اسکن، حساس‌ترین چیزی است که یک سازمان به ما می‌سپارد. به همین دلیل محافظت از آن بخشی از خود محصول است، نه یک وعده."
               tinted>
        <ul className="grid sm:grid-cols-2 gap-x-12 gap-y-5">
          {[
            "ورود دو عاملی برای همهٔ حساب‌ها",
            "جداسازی مستأجرها در سمت سرور — با دستکاری پارامتر هم دور نمی‌خورد",
            "دفتر رویدادهای تغییرناپذیر با زنجیرهٔ درهم‌سازی",
            "امکان استقرار داخل دیتاسنتر خودتان، بدون خروج داده",
          ].map(item => (
            <li key={item} className="flex items-start gap-3 text-[13px] text-muted-foreground leading-relaxed">
              <ShieldCheck size={15} className="text-primary flex-shrink-0 mt-0.5" />
              {item}
            </li>
          ))}
        </ul>
      </Section>

      <section className="border-t border-border">
        <div className="max-w-6xl mx-auto w-full px-5 py-20 text-center">
          <h2 className="text-2xl sm:text-3xl font-bold text-foreground mb-4 leading-snug">
            ببینید شبکهٔ شما از بیرون چه شکلی است
          </h2>
          <p className="text-[13px] text-muted-foreground leading-relaxed max-w-lg mx-auto mb-9">
            درخواست خود را ثبت کنید؛ کارشناسان افرانت برای تعیین محدودهٔ اسکن با شما تماس می‌گیرند.
          </p>
          <button onClick={onRequestAccess}
            className="inline-flex items-center gap-2 text-sm bg-primary text-primary-foreground rounded
                       px-7 py-3.5 hover:opacity-90 transition-opacity">
            درخواست دسترسی <ArrowLeft size={14} />
          </button>
        </div>
      </section>

      <footer className="border-t border-border py-6 px-5 text-center text-[12px] text-muted-foreground">
        افرانت ® افراکاو — مدیریت آسیب‌پذیری · <span dir="ltr">soc@afranet.ir</span>
      </footer>
    </div>
  );
}

// ── page furniture ──────────────────────────────────────────────────────────

/**
 * Sections are numbered because the page really is a sequence — proof, method,
 * product, trust — and a reader who skips around benefits from knowing where
 * they are in it.
 */
function Section({ index, title, lede, tinted, children }: {
  index: string;
  title: string;
  lede?: string;
  tinted?: boolean;
  children: React.ReactNode;
}) {
  return (
    <section className={`border-t border-border ${tinted ? "bg-card/30" : ""}`}>
      <div className="max-w-6xl mx-auto w-full px-5 py-16 sm:py-20">
        <div className="flex items-baseline gap-3 mb-2">
          <span className="font-mono text-[12px] text-primary/70">{index}</span>
          <h2 className="text-xl sm:text-2xl font-bold text-foreground tracking-tight">{title}</h2>
        </div>
        <p className={`text-[13px] text-muted-foreground leading-relaxed max-w-2xl ${lede ? "mb-9" : "mb-7"}`}>
          {lede}
        </p>
        {children}
      </div>
    </section>
  );
}

// ── the hero readout ────────────────────────────────────────────────────────

/**
 * A scanner's-eye view of the sample, beside the headline. Same data as the
 * section below, compressed to the shape a tool would print it in — the most
 * honest way to show what the product actually does.
 */
function ScanReadout({ showcase, loading }: { showcase: Showcase | null; loading: boolean }) {
  if (loading) {
    return (
      <div className="rounded border border-border flex items-center justify-center py-24"
           style={{ background: "var(--terminal-bg)" }}>
        <Loader2 size={18} className="animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (!showcase || showcase.hosts.length === 0) return null;

  return (
    <div className="rounded border border-border overflow-hidden"
         style={{ background: "var(--terminal-bg)" }}>
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-card/40">
        <Radar size={12} className="text-primary" />
        <span className="text-[11px] text-foreground">خروجی اسکن</span>
        <span className="ms-auto flex items-center gap-1.5 text-[10px] text-muted-foreground">
          <span className="live-dot w-1.5 h-1.5 rounded-full bg-[#2ea043]" />
          نمونهٔ واقعی
        </span>
      </div>

      <div className="py-2">
        {showcase.hosts.slice(0, 6).map((h, i) => {
          const worst = h.vulns.find(v => v.severity === "Critical")
            ?? h.vulns.find(v => v.severity === "High")
            ?? h.vulns[0];
          return (
            <div key={`${h.ip}-${i}`}
                 className="scan-line flex items-center gap-3 px-4 py-1.5 text-[11px] font-mono"
                 style={{ animationDelay: `${i * 90}ms` }}>
              <span className="text-primary w-[5.5rem] flex-shrink-0" dir="ltr">{h.ip}</span>
              <span className="text-muted-foreground truncate flex-1 min-w-0" dir="ltr">
                {h.ports.slice(0, 3).map(p => `${p.port}/${p.service || "?"}`).join("  ") || "—"}
              </span>
              {worst ? (
                <span className="flex items-center gap-1.5 flex-shrink-0"
                      style={{ color: SEV_COLOR[worst.severity] }}>
                  <span className="w-1.5 h-1.5 rounded-sm" style={{ background: SEV_COLOR[worst.severity] }} />
                  {SEV_FA[worst.severity]}
                </span>
              ) : (
                <span className="text-[#2ea043] flex-shrink-0">پاک</span>
              )}
            </div>
          );
        })}
      </div>

      <div className="px-4 py-2.5 border-t border-border bg-card/40 flex items-center gap-2 text-[11px]">
        <ShieldCheck size={11} className="text-primary flex-shrink-0" />
        <span className="text-muted-foreground">
          {faNum(showcase.stats.hosts)} میزبان بررسی شد · {faNum(showcase.stats.findings)} یافته
        </span>
        <span className="ms-auto text-[10px] text-muted-foreground/70 font-mono">
          <span dir="ltr">×.× masked</span>
        </span>
      </div>
    </div>
  );
}

// ── stats band ──────────────────────────────────────────────────────────────

function StatsBand({ showcase }: { showcase: Showcase }) {
  const { stats } = showcase;
  const items = [
    { label: "میزبان اسکن‌شده", value: stats.hosts },
    { label: "پورت باز", value: stats.openPorts },
    { label: "یافته", value: stats.findings },
    { label: "CVE یکتا", value: stats.cves },
  ];
  return (
    <section className="border-t border-border bg-card/30">
      <div className="max-w-6xl mx-auto w-full px-5">
        <div className="grid grid-cols-2 sm:grid-cols-4">
          {items.map((it, i) => (
            <div key={it.label}
                 className={`py-8 px-4 text-center ${i > 0 ? "sm:border-s sm:border-border" : ""}`}>
              <div className="text-3xl sm:text-4xl font-bold text-primary tabular-nums tracking-tight">
                {faNum(it.value)}
              </div>
              <div className="text-[11px] text-muted-foreground mt-2">{it.label}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── the full sample ─────────────────────────────────────────────────────────

function ShowcaseList({ showcase }: { showcase: Showcase }) {
  const { stats } = showcase;
  const severities = (["Critical", "High", "Medium", "Low"] as const)
    .map(s => ({ s, n: stats.bySeverity[s] ?? 0 }))
    .filter(x => x.n > 0);

  return (
    <div className="border border-border rounded overflow-hidden bg-card">
      <div className="px-4 sm:px-5 py-3.5 border-b border-border flex items-center gap-4 flex-wrap">
        {severities.map(({ s, n }) => (
          <span key={s} className="flex items-center gap-1.5 text-[12px] text-muted-foreground">
            <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ background: SEV_COLOR[s] }} />
            {SEV_FA[s]}
            <span className="font-mono tabular-nums text-foreground">{faNum(n)}</span>
          </span>
        ))}
        {/* The privacy promise sits with the data it is about, not in a footnote. */}
        <span className="ms-auto flex items-center gap-2 text-[11px] text-muted-foreground max-w-md">
          <EyeOff size={12} className="text-primary flex-shrink-0" />
          نشانی‌ها ناقص‌اند؛ نام میزبان، دامنه، نام سازمان و بنر سرویس‌ها اصلاً منتشر نمی‌شوند.
        </span>
      </div>

      <div className="divide-y divide-border">
        {showcase.hosts.slice(0, 8).map((h, i) => <ShowcaseRow key={`${h.ip}-${i}`} host={h} />)}
      </div>

      {showcase.hosts.length > 8 && (
        <p className="px-5 py-3 border-t border-border text-[12px] text-muted-foreground text-center">
          و {faNum(showcase.hosts.length - 8)} میزبان دیگر در همین اسکن.
        </p>
      )}
    </div>
  );
}

function ShowcaseRow({ host }: { host: ShowcaseHost }) {
  const crit = host.vulns.filter(v => v.severity === "Critical").length;
  const high = host.vulns.filter(v => v.severity === "High").length;
  const cves = host.vulns.map(v => v.cve).filter(Boolean) as string[];

  return (
    <div className="px-4 sm:px-5 py-4 hover:bg-secondary/20 transition-colors">
      <div className="flex items-center gap-2.5 flex-wrap mb-2.5">
        {/* The masked address is the headline, exactly where a full one would
            sit on a Shodan result — the redaction is meant to be noticed. */}
        <span className="font-mono font-bold text-primary text-[15px]" dir="ltr">{host.ip}</span>
        {crit > 0 && (
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border
                           text-[#ff3b3b] border-[#ff3b3b]/25 bg-[#ff3b3b]/5">
            {faNum(crit)} بحرانی
          </span>
        )}
        {high > 0 && (
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border
                           text-[#ff8c00] border-[#ff8c00]/25 bg-[#ff8c00]/5">
            {faNum(high)} بالا
          </span>
        )}
        {host.vulns.length === 0 && (
          <span className="flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 rounded border
                           text-[#2ea043] border-[#2ea043]/25 bg-[#2ea043]/5">
            <ShieldCheck size={9} /> بدون یافته
          </span>
        )}
        {/* dir="ltr" belongs on the text, not on the flex item: a logical
            margin resolves against the element's OWN direction, so ms-auto on
            an ltr element would push the wrong way inside this rtl row. */}
        {host.os && (
          <span className="ms-auto text-[11px] text-muted-foreground">
            <span dir="ltr">{host.os}</span>
          </span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        {host.ports.slice(0, 10).map(p => (
          <span key={`${p.port}-${p.proto}`} dir="ltr"
            className="text-[11px] font-mono border border-border bg-secondary/40 rounded px-1.5 py-0.5 text-muted-foreground">
            <span className="text-foreground font-bold">{p.port}</span>
            {p.service && <span className="opacity-70">/{p.service}</span>}
          </span>
        ))}
        {host.ports.length > 10 && (
          <span className="text-[11px] text-muted-foreground">+{faNum(host.ports.length - 10)}</span>
        )}

        {cves.length > 0 && (
          <span className="flex flex-wrap items-center gap-1 ms-auto">
            {cves.slice(0, 4).map(cve => (
              <span key={cve} dir="ltr"
                className="text-[10px] font-mono px-1.5 py-0.5 rounded border
                           text-[#ff3b3b]/80 border-[#ff3b3b]/20 bg-[#ff3b3b]/5">
                {cve}
              </span>
            ))}
            {cves.length > 4 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded border border-border text-muted-foreground">
                {faNum(cves.length - 4)}+
              </span>
            )}
          </span>
        )}
      </div>
    </div>
  );
}
