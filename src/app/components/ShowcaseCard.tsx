import { useEffect, useRef, useState } from "react";
import {
  Globe, FileText, Loader2, CheckCircle, AlertTriangle, Trash2, EyeOff,
} from "lucide-react";
import { Showcase, clearShowcase, fetchShowcase, publishShowcase } from "../api";
import { faNum, faDate } from "../format";

const MASK_OPTIONS = [
  { octets: 2, label: "۲ بخش", example: "203.0.×.×", hint: "پیشنهادشده" },
  { octets: 1, label: "۱ بخش", example: "203.0.113.×", hint: "زیرشبکه آشکار می‌ماند" },
  { octets: 3, label: "۳ بخش", example: "203.×.×.×", hint: "محتاطانه‌ترین" },
];

/**
 * Publishes an anonymised sample scan to the public landing page.
 *
 * The file is redacted server-side before it is stored, so what ends up public
 * is never the file that was uploaded. This card's job is to make the operator
 * aware of what that redaction does and does not cover before they publish a
 * real customer's scan.
 */
export default function ShowcaseCard() {
  const [current, setCurrent] = useState<Showcase | null>(null);
  const [label, setLabel] = useState("");
  const [maskOctets, setMaskOctets] = useState(2);
  const [file, setFile] = useState<File | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const refresh = () => {
    fetchShowcase()
      .then(res => setCurrent(res.published && res.showcase ? res.showcase : null))
      .catch(() => setCurrent(null));
  };
  useEffect(refresh, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setBusy(true); setMsg(null);
    try {
      const res = await publishShowcase(file, maskOctets, label.trim());
      setMsg({
        ok: true,
        text: `منتشر شد — ${faNum(res.scannedHosts)} میزبان اسکن‌شده، ${faNum(res.sampleHosts)} میزبان در نمونه.`,
      });
      setFile(null);
      if (inputRef.current) inputRef.current.value = "";
      refresh();
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || "انتشار ناموفق بود" });
    } finally { setBusy(false); }
  };

  const remove = async () => {
    if (!confirm("نمونهٔ اسکن از صفحهٔ نخست برداشته شود؟")) return;
    setBusy(true); setMsg(null);
    try {
      await clearShowcase();
      setMsg({ ok: true, text: "نمونه از صفحهٔ نخست برداشته شد." });
      refresh();
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || "حذف ناموفق بود" });
    } finally { setBusy(false); }
  };

  return (
    <div className="bg-card border border-border rounded p-4">
      <div className="flex items-center gap-2 mb-3">
        <Globe size={13} className="text-primary" />
        <span className="text-xs font-semibold text-foreground">نمونهٔ اسکن صفحهٔ نخست</span>
        {current && (
          <span className="ms-auto text-[10px] text-primary border border-primary/30 bg-primary/5 rounded px-1.5 py-0.5">
            منتشرشده
          </span>
        )}
      </div>

      {/* What the operator is actually agreeing to, stated before the form. */}
      <div className="flex items-start gap-2 mb-3 text-[11px] text-muted-foreground leading-relaxed
                      border border-border rounded px-2.5 py-2 bg-secondary/20">
        <EyeOff size={12} className="text-primary flex-shrink-0 mt-0.5" />
        <p>
          این اسکن برای <span className="text-foreground">همه</span> قابل دیدن می‌شود. پیش از ذخیره،
          نشانی‌ها ناقص می‌شوند و نام میزبان، دامنه، نام سازمان و بنر سرویس‌ها حذف می‌شوند —
          دادهٔ خام اصلاً ذخیره نمی‌شود. با این حال نوع سرویس‌ها و آسیب‌پذیری‌ها منتشر می‌شود،
          پس فقط اسکنی را انتخاب کنید که انتشارش با مشتری هماهنگ شده باشد.
        </p>
      </div>

      {current && (
        <div className="mb-3 text-[11px] text-muted-foreground border border-border rounded px-2.5 py-2 space-y-0.5">
          <p>
            اکنون منتشر شده: <span className="text-foreground">{faNum(current.stats.hosts)}</span> میزبان اسکن‌شده،
            {" "}<span className="text-foreground">{faNum(current.hosts.length)}</span> میزبان در نمونه،
            {" "}<span className="text-foreground">{faNum(current.stats.findings)}</span> یافته
          </p>
          <p>
            تاریخ انتشار: {faDate(current.publishedAt)} · پنهان‌سازی نشانی:
            {" "}{faNum(current.maskOctets)} بخش
          </p>
        </div>
      )}

      <form onSubmit={submit} className="space-y-2.5">
        <div>
          <label className="text-[11px] text-muted-foreground">میزان پنهان‌سازی نشانی</label>
          <div className="mt-1 grid grid-cols-3 gap-1.5">
            {MASK_OPTIONS.map(opt => (
              <button key={opt.octets} type="button" onClick={() => setMaskOctets(opt.octets)}
                title={opt.hint}
                className={`py-1.5 px-1 rounded border text-center transition-colors ${
                  maskOctets === opt.octets
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border text-muted-foreground hover:border-primary/40"
                }`}>
                <span className="block text-[11px]">{opt.label}</span>
                <span className="block text-[10px] font-mono opacity-70" dir="ltr">{opt.example}</span>
              </button>
            ))}
          </div>
          {maskOctets === 1 && (
            <p className="mt-1.5 text-[10px] text-[#ff8c00] leading-relaxed">
              با پنهان‌سازی یک بخش، زیرشبکهٔ ‎/24 آشکار می‌ماند و برای نشانی‌های عمومی از طریق
              رجیستری مسیریابی قابل انتساب به صاحبش است.
            </p>
          )}
        </div>

        <div>
          <label className="text-[11px] text-muted-foreground">عنوان (اختیاری)</label>
          <input value={label} onChange={e => setLabel(e.target.value)}
            placeholder="مثلاً: اسکن نمونهٔ شبکهٔ سازمانی"
            className="mt-1 w-full py-2 px-2 bg-secondary border border-border rounded text-sm text-foreground
                       placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40" />
        </div>

        <div>
          <label className="text-[11px] text-muted-foreground">
            فایل اسکن <span dir="ltr" className="font-mono">(.nessus)</span>
          </label>
          <button type="button" onClick={() => inputRef.current?.click()}
            className="mt-1 w-full flex items-center gap-2 py-2 px-3 bg-secondary border border-border rounded
                       text-xs text-muted-foreground hover:border-primary/40 transition-colors">
            <FileText size={13} className="text-primary flex-shrink-0" />
            <span className="truncate font-mono" dir="ltr">{file ? file.name : "انتخاب فایل…"}</span>
          </button>
          <input ref={inputRef} type="file" accept=".nessus,.xml" className="hidden"
            onChange={e => setFile(e.target.files?.[0] ?? null)} />
        </div>

        <Msg msg={msg} />

        <div className="flex items-center gap-2">
          <button type="submit" disabled={busy || !file}
            className="flex-1 flex items-center justify-center gap-2 py-2 rounded bg-primary/15 border
                       border-primary/30 text-primary text-xs hover:bg-primary/25 transition-colors
                       disabled:opacity-40">
            {busy ? <Loader2 size={13} className="animate-spin" /> : <Globe size={12} />}
            انتشار در صفحهٔ نخست
          </button>
          {current && (
            <button type="button" onClick={remove} disabled={busy} title="برداشتن از صفحهٔ نخست"
              className="py-2 px-2.5 rounded border border-border text-muted-foreground
                         hover:text-[#ff3b3b] hover:border-[#ff3b3b]/30 transition-colors disabled:opacity-40">
              <Trash2 size={13} />
            </button>
          )}
        </div>
      </form>
    </div>
  );
}

function Msg({ msg }: { msg: { ok: boolean; text: string } | null }) {
  if (!msg) return null;
  return (
    <div className={`flex items-start gap-2 text-[12px] rounded px-2.5 py-1.5 border ${
      msg.ok ? "text-primary border-primary/25 bg-primary/5" : "text-[#ff3b3b] border-[#ff3b3b]/25 bg-[#ff3b3b]/5"
    }`}>
      {msg.ok
        ? <CheckCircle size={12} className="mt-0.5 flex-shrink-0" />
        : <AlertTriangle size={12} className="mt-0.5 flex-shrink-0" />}
      <span className="leading-relaxed">{msg.text}</span>
    </div>
  );
}
