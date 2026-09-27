import { useEffect, useState } from "react";
import {
  Search, ShieldCheck, Activity, Crosshair, TrendingDown, Lock,
  ArrowLeft, Loader2, Server, EyeOff, ScrollText, Building2,
} from "lucide-react";
import { Showcase, ShowcaseHost, fetchShowcase } from "./api";
import { faNum } from "./format";
import { SEV_COLOR, SEV_FA } from "./components/severity";
import Brand from "./components/Brand";
import ThemeToggle from "./components/ThemeToggle";

/**
 * The public front door.
 *
 * The sample scan is the page's centre of gravity — a visitor believes "we can
 * see your attack surface" far more readily when shown real findings than when
 * told. What makes that safe is that the backend redacted the scan when it was
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
      .catch(() => { /* the section simply does not render */ })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <nav className="border-b border-border bg-card/60 backdrop-blur sticky top-0 z-40">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-4">
          <Brand className="h-7" />
          <span className="text-[11px] text-muted-foreground border-s border-border ps-2 hidden sm:block">
            مدیریت آسیب‌پذیری
          </span>
          <div className="ms-auto flex items-center gap-3">
            <ThemeToggle />
            <button onClick={onSignIn}
              className="flex items-center gap-1.5 text-xs text-foreground border border-border hover:border-primary/40
                         hover:text-primary rounded px-3 py-1.5 transition-colors">
              <Lock size={12} /> ورود
            </button>
          </div>
        </div>
      </nav>

      {/* ── hero ── */}
      <header className="max-w-5xl mx-auto w-full px-4 pt-16 pb-12 sm:pt-24 sm:pb-16">
        <p className="text-[12px] text-primary mb-4">سرویس مدیریت آسیب‌پذیری افرانت</p>
        <h1 className="text-3xl sm:text-5xl font-bold text-foreground leading-[1.35] tracking-tight max-w-3xl">
          شبکهٔ خود را از بیرون ببینید،
          <br />
          <span className="text-primary">پیش از آنکه دیگری ببیند.</span>
        </h1>
        <p className="mt-6 text-sm sm:text-base text-muted-foreground leading-loose max-w-2xl">
          افراکاو زیرساخت سازمان شما را به‌صورت دوره‌ای اسکن می‌کند، پورت‌های باز و سرویس‌های
          در معرض را فهرست می‌کند، آسیب‌پذیری‌ها را بر اساس قابلیت بهره‌برداری اولویت‌بندی می‌کند،
          و نشان می‌دهد وضعیت شما نسبت به اسکن قبل بهتر شده یا بدتر.
        </p>

        <div className="mt-8 flex flex-wrap items-center gap-3">
          <button onClick={onRequestAccess}
            className="flex items-center gap-2 text-sm bg-primary text-primary-foreground rounded px-5 py-2.5
                       hover:opacity-90 transition-opacity">
            درخواست دسترسی <ArrowLeft size={14} />
          </button>
          <button onClick={onSignIn}
            className="text-sm text-muted-foreground hover:text-primary border border-border
                       hover:border-primary/30 rounded px-5 py-2.5 transition-colors">
            ورود مشتریان
          </button>
        </div>
      </header>

      {/* ── the sample scan ── */}
      <section className="max-w-5xl mx-auto w-full px-4 pb-16">
        {loading ? (
          <div className="border border-border rounded bg-card py-16 flex justify-center text-muted-foreground">
            <Loader2 size={20} className="animate-spin" />
          </div>
        ) : showcase ? (
          <ShowcaseSection showcase={showcase} />
        ) : null}
      </section>

      {/* ── how it works ── */}
      <section className="border-y border-border bg-card/40">
        <div className="max-w-5xl mx-auto w-full px-4 py-14">
          <h2 className="text-xl font-bold text-foreground mb-2">چطور کار می‌کند</h2>
          <p className="text-[13px] text-muted-foreground mb-8 max-w-xl leading-relaxed">
            سرویس مدیریت‌شده است؛ لازم نیست چیزی نصب کنید یا ابزاری بخرید.
          </p>

          <ol className="grid sm:grid-cols-3 gap-6">
            {[
              {
                n: "۱", title: "اسکن دوره‌ای",
                body: "کارشناسان افرانت محدودهٔ توافق‌شده را در دوره‌های شش‌ماهه تا هفتگی اسکن می‌کنند. چیزی روی سرورهای شما نصب نمی‌شود.",
              },
              {
                n: "۲", title: "تحلیل و اولویت‌بندی",
                body: "یافته‌ها بررسی و خطاهای مثبت کاذب کنار گذاشته می‌شوند. آنچه اکسپلویت منتشرشده دارد، بالاتر از نمرهٔ CVSS می‌نشیند.",
              },
              {
                n: "۳", title: "پایش روند",
                body: "هر اسکن به وضعیت کل شبکه اضافه می‌شود تا ببینید چه چیزی رفع شده و چه چیزی تازه پیدا شده است.",
              },
            ].map(step => (
              <li key={step.n} className="flex flex-col gap-2">
                <span className="text-primary font-mono text-sm">{step.n}</span>
                <h3 className="text-sm font-semibold text-foreground">{step.title}</h3>
                <p className="text-[13px] text-muted-foreground leading-relaxed">{step.body}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* ── what the panel gives you ── */}
      <section className="max-w-5xl mx-auto w-full px-4 py-14">
        <h2 className="text-xl font-bold text-foreground mb-8">آنچه در پنل می‌بینید</h2>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-px bg-border border border-border rounded overflow-hidden">
          {[
            { icon: Search, title: "جست‌وجوی شبکه", body: "هر IP، نام میزبان، پورت، سرویس یا CVE را در دارایی‌های خود پیدا کنید." },
            { icon: Activity, title: "اولویت‌بندی بر پایهٔ اکسپلویت", body: "یافته‌هایی که اکسپلویت عمومی دارند جدا می‌شوند؛ اینها اول رفع می‌شوند." },
            { icon: Crosshair, title: "نگاشت MITRE ATT&CK", body: "هر ضعف به تکنیک‌هایی که مهاجم می‌تواند اجرا کند نگاشت می‌شود، با ذکر منبع نگاشت." },
            { icon: TrendingDown, title: "روند بهبود", body: "نمودار یافته‌ها در طول زمان؛ پاسخ روشن به «آیا بهتر شدیم؟»." },
            { icon: ScrollText, title: "گزارش رویدادها", body: "هر ورود، خروج و اقدام مدیریتی در یک دفتر تغییرناپذیر ثبت می‌شود." },
            { icon: Building2, title: "جداسازی کامل", body: "داده‌های هر سازمان در سمت سرور جدا می‌شود؛ دیدن دادهٔ سازمان دیگر ممکن نیست." },
          ].map(f => (
            <div key={f.title} className="bg-card p-5 flex flex-col gap-2">
              <f.icon size={15} className="text-primary" />
              <h3 className="text-sm font-semibold text-foreground">{f.title}</h3>
              <p className="text-[13px] text-muted-foreground leading-relaxed">{f.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── trust ── */}
      <section className="border-t border-border bg-card/40">
        <div className="max-w-5xl mx-auto w-full px-4 py-14">
          <h2 className="text-xl font-bold text-foreground mb-3">دادهٔ شما چطور نگهداری می‌شود</h2>
          <p className="text-[13px] text-muted-foreground leading-loose max-w-2xl mb-8">
            نتیجهٔ اسکن، حساس‌ترین چیزی است که یک سازمان به ما می‌سپارد. به همین دلیل
            محافظت از آن بخشی از خود محصول است، نه یک وعده.
          </p>
          <ul className="grid sm:grid-cols-2 gap-x-10 gap-y-4 max-w-3xl">
            {[
              "ورود دو عاملی برای همهٔ حساب‌ها",
              "جداسازی مستأجرها در سمت سرور — با دستکاری پارامتر هم دور نمی‌خورد",
              "دفتر رویدادهای تغییرناپذیر با زنجیرهٔ درهم‌سازی",
              "امکان استقرار داخل دیتاسنتر خودتان، بدون خروج داده",
            ].map(item => (
              <li key={item} className="flex items-start gap-2.5 text-[13px] text-muted-foreground leading-relaxed">
                <ShieldCheck size={14} className="text-primary flex-shrink-0 mt-0.5" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* ── closing call to action ── */}
      <section className="max-w-5xl mx-auto w-full px-4 py-16 text-center">
        <h2 className="text-2xl font-bold text-foreground mb-3">ببینید شبکهٔ شما از بیرون چه شکلی است</h2>
        <p className="text-[13px] text-muted-foreground leading-relaxed max-w-lg mx-auto mb-7">
          درخواست خود را ثبت کنید؛ کارشناسان افرانت برای تعیین محدودهٔ اسکن با شما تماس می‌گیرند.
        </p>
        <button onClick={onRequestAccess}
          className="inline-flex items-center gap-2 text-sm bg-primary text-primary-foreground rounded px-6 py-3
                     hover:opacity-90 transition-opacity">
          درخواست دسترسی <ArrowLeft size={14} />
        </button>
      </section>

      <footer className="mt-auto border-t border-border py-5 px-4 text-center text-[12px] text-muted-foreground">
        افرانت ® افراکاو — مدیریت آسیب‌پذیری · <span dir="ltr">soc@afranet.ir</span>
      </footer>
    </div>
  );
}

// ── the sample scan ─────────────────────────────────────────────────────────

function ShowcaseSection({ showcase }: { showcase: Showcase }) {
  const { stats } = showcase;
  const severities = (["Critical", "High", "Medium", "Low"] as const)
    .map(s => ({ s, n: stats.bySeverity[s] ?? 0 }))
    .filter(x => x.n > 0);

  return (
    <div className="border border-border rounded bg-card overflow-hidden">
      <div className="px-4 sm:px-5 py-4 border-b border-border flex items-start gap-3 flex-wrap">
        <div className="flex-1 min-w-[16rem]">
          <h2 className="text-sm font-semibold text-foreground mb-1">نمونه‌ای از یک اسکن واقعی</h2>
          <p className="text-[12px] text-muted-foreground leading-relaxed">
            این نتایج از اسکن واقعی یک شبکه گرفته شده است.
          </p>
        </div>
        {/* The privacy promise sits with the data it is about, not in a footnote. */}
        <div className="flex items-start gap-2 text-[11px] text-muted-foreground max-w-sm
                        border border-border rounded px-2.5 py-2 bg-secondary/20">
          <EyeOff size={12} className="text-primary flex-shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            نشانی‌ها به‌صورت ناقص نمایش داده می‌شوند و نام میزبان، دامنه، نام سازمان و
            بنر سرویس‌ها اصلاً منتشر نمی‌شوند.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 divide-x divide-x-reverse divide-border border-b border-border">
        <Metric label="میزبان اسکن‌شده" value={faNum(stats.hosts)} />
        <Metric label="پورت باز" value={faNum(stats.openPorts)} />
        <Metric label="یافته" value={faNum(stats.findings)} />
        <Metric label="CVE یکتا" value={faNum(stats.cves)} />
      </div>

      {severities.length > 0 && (
        <div className="px-4 sm:px-5 py-3 border-b border-border flex flex-wrap items-center gap-x-5 gap-y-2">
          {severities.map(({ s, n }) => (
            <span key={s} className="flex items-center gap-1.5 text-[12px] text-muted-foreground">
              <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ background: SEV_COLOR[s] }} />
              {SEV_FA[s]}
              <span className="font-mono tabular-nums text-foreground">{faNum(n)}</span>
            </span>
          ))}
        </div>
      )}

      <div className="divide-y divide-border">
        {showcase.hosts.slice(0, 8).map((h, i) => <ShowcaseCard key={`${h.ip}-${i}`} host={h} />)}
      </div>

      {showcase.hosts.length > 8 && (
        <p className="px-4 sm:px-5 py-3 border-t border-border text-[12px] text-muted-foreground text-center">
          و {faNum(showcase.hosts.length - 8)} میزبان دیگر در همین اسکن.
        </p>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="px-4 py-4 text-center">
      <div className="text-xl sm:text-2xl font-bold text-primary tabular-nums">{value}</div>
      <div className="text-[11px] text-muted-foreground mt-1">{label}</div>
    </div>
  );
}

function ShowcaseCard({ host }: { host: ShowcaseHost }) {
  const crit = host.vulns.filter(v => v.severity === "Critical").length;
  const high = host.vulns.filter(v => v.severity === "High").length;
  const cves = host.vulns.map(v => v.cve).filter(Boolean) as string[];

  return (
    <div className="px-4 sm:px-5 py-4">
      <div className="flex items-center gap-2.5 flex-wrap mb-2">
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
          <span className="ms-auto flex items-center gap-1 text-[11px] text-muted-foreground">
            <Server size={10} /> <span dir="ltr">{host.os}</span>
          </span>
        )}
      </div>

      {host.ports.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-2">
          {host.ports.slice(0, 10).map(p => (
            <span key={`${p.port}-${p.proto}`} dir="ltr"
              className="text-[11px] font-mono border border-border bg-secondary/40 rounded px-1.5 py-0.5 text-muted-foreground">
              <span className="text-foreground font-bold">{p.port}</span>
              {p.service && <span className="opacity-70">/{p.service}</span>}
            </span>
          ))}
          {host.ports.length > 10 && (
            <span className="text-[11px] text-muted-foreground px-1.5 py-0.5">
              +{faNum(host.ports.length - 10)}
            </span>
          )}
        </div>
      )}

      {cves.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {cves.slice(0, 5).map(cve => (
            <span key={cve} dir="ltr"
              className="text-[10px] font-mono px-1.5 py-0.5 rounded border
                         text-[#ff3b3b]/80 border-[#ff3b3b]/20 bg-[#ff3b3b]/5">
              {cve}
            </span>
          ))}
          {cves.length > 5 && (
            <span className="text-[10px] px-1.5 py-0.5 rounded border border-border text-muted-foreground">
              {faNum(cves.length - 5)} مورد دیگر
            </span>
          )}
        </div>
      )}
    </div>
  );
}
