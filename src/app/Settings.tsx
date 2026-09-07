import { useEffect, useRef, useState } from "react";
import {
  ShieldCheck, ShieldOff, KeyRound, Loader2, CheckCircle, AlertTriangle,
  Copy, Download, ArrowRight, Smartphone,
} from "lucide-react";
import QRCode from "qrcode";
import { useAuth } from "./auth";
import {
  startTwoFactorSetup, enableTwoFactor, disableTwoFactor, changePassword, me,
} from "./api";

const faNum = (n: number) => n.toLocaleString("fa-IR");

export default function Settings({ onBack }: { onBack: () => void }) {
  const { user, refresh } = useAuth();
  const [recoveryLeft, setRecoveryLeft] = useState<number | null>(null);

  useEffect(() => {
    me().then(m => setRecoveryLeft(m.recoveryCodesRemaining)).catch(() => {});
  }, [user?.totpEnabled]);

  return (
    <div className="max-w-2xl mx-auto w-full px-4 py-8 space-y-4">
      <div className="flex items-center gap-3">
        <button onClick={onBack}
          className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-primary border border-border hover:border-primary/30 rounded px-2 py-1.5 transition-colors">
          <ArrowRight size={12} /> بازگشت
        </button>
        <h1 className="text-lg font-bold text-foreground">تنظیمات حساب</h1>
      </div>

      <TwoFactorCard
        enabled={!!user?.totpEnabled}
        recoveryLeft={recoveryLeft}
        onChanged={() => { refresh(); }}
      />
      <PasswordCard />
    </div>
  );
}

// ── two-factor ───────────────────────────────────────────────────────────────

type Stage = "idle" | "scanning" | "codes";

function TwoFactorCard({ enabled, recoveryLeft, onChanged }: {
  enabled: boolean;
  recoveryLeft: number | null;
  onChanged: () => void;
}) {
  const [stage, setStage] = useState<Stage>("idle");
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [qr, setQr] = useState<string>("");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [codes, setCodes] = useState<string[]>([]);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  // The QR is drawn in the browser: the CSP allows no external image source,
  // and the secret should not travel to a third party to be rendered.
  useEffect(() => {
    if (!setup) { setQr(""); return; }
    QRCode.toDataURL(setup.uri, { margin: 1, width: 220, errorCorrectionLevel: "M" })
      .then(setQr)
      .catch(() => setQr(""));
  }, [setup]);

  const begin = async () => {
    setBusy(true); setMsg(null);
    try {
      setSetup(await startTwoFactorSetup());
      setStage("scanning");
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || "شروع فعال‌سازی ناموفق بود" });
    } finally { setBusy(false); }
  };

  const confirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try {
      setCodes(await enableTwoFactor(code.trim()));
      setStage("codes");
      setCode(""); setSetup(null);
      onChanged();
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || "کد تأیید پذیرفته نشد" });
    } finally { setBusy(false); }
  };

  const turnOff = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!confirm2("با غیرفعال‌کردن ورود دو عاملی، حساب شما فقط با رمز عبور محافظت می‌شود. ادامه می‌دهید؟")) return;
    setBusy(true); setMsg(null);
    try {
      await disableTwoFactor(password);
      setPassword("");
      setMsg({ ok: true, text: "ورود دو عاملی غیرفعال شد." });
      onChanged();
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || "غیرفعال‌سازی ناموفق بود" });
    } finally { setBusy(false); }
  };

  return (
    <section className="bg-card border border-border rounded overflow-hidden">
      <div className="px-4 py-3 border-b border-border bg-secondary/20 flex items-center gap-2">
        {enabled ? <ShieldCheck size={14} className="text-primary" /> : <ShieldOff size={14} className="text-muted-foreground" />}
        <span className="text-xs font-semibold text-foreground">ورود دو عاملی</span>
        <span className={`ms-auto text-[10px] rounded px-1.5 py-0.5 border ${
          enabled
            ? "text-primary border-primary/30 bg-primary/5"
            : "text-muted-foreground border-border"
        }`}>
          {enabled ? "فعال" : "غیرفعال"}
        </span>
      </div>

      <div className="p-4 space-y-3">
        {stage === "codes" ? (
          <RecoveryCodes codes={codes} onDone={() => { setStage("idle"); setCodes([]); }} />
        ) : enabled ? (
          <>
            <p className="text-[12px] text-muted-foreground leading-relaxed">
              ورود به حساب شما علاوه بر رمز عبور، به کد شش‌رقمی برنامهٔ احرازکنندهٔ شما نیاز دارد.
              {recoveryLeft !== null && (
                <> در حال حاضر <span className="text-foreground font-mono">{faNum(recoveryLeft)}</span> کد بازیابی استفاده‌نشده دارید.</>
              )}
            </p>
            <form onSubmit={turnOff} className="space-y-2.5 pt-1">
              <label className="text-[10px] text-muted-foreground">
                برای غیرفعال‌کردن، رمز عبور فعلی خود را وارد کنید
              </label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)} dir="ltr"
                className="w-full py-2 px-2 bg-secondary border border-border rounded text-sm font-mono text-foreground focus:outline-none focus:border-primary/40" />
              <Msg msg={msg} />
              <button type="submit" disabled={busy || !password}
                className="flex items-center gap-2 py-2 px-3 rounded border border-[#ff3b3b]/30 bg-[#ff3b3b]/5 text-[#ff3b3b] text-xs hover:bg-[#ff3b3b]/10 transition-colors disabled:opacity-40">
                {busy ? <Loader2 size={13} className="animate-spin" /> : <ShieldOff size={12} />} غیرفعال‌کردن ورود دو عاملی
              </button>
            </form>
          </>
        ) : stage === "scanning" && setup ? (
          <>
            <ol className="text-[12px] text-muted-foreground leading-relaxed space-y-1 list-decimal ps-4">
              <li>برنامهٔ احرازکننده (Google Authenticator، Aegis، 1Password و مانند آن) را باز کنید.</li>
              <li>کد QR زیر را اسکن کنید، یا کلید متنی را دستی وارد کنید.</li>
              <li>کد شش‌رقمی نمایش‌داده‌شده را در کادر پایین بنویسید.</li>
            </ol>

            <div className="flex flex-col sm:flex-row items-center gap-4 py-2">
              {qr
                ? <img src={qr} alt="کد QR برای برنامهٔ احرازکننده" width={180} height={180}
                       className="rounded border border-border bg-white p-1 flex-shrink-0" />
                : <div className="w-[180px] h-[180px] rounded border border-border flex items-center justify-center text-muted-foreground flex-shrink-0">
                    <Loader2 size={18} className="animate-spin" />
                  </div>}
              <div className="flex-1 min-w-0 w-full space-y-1.5">
                <p className="text-[10px] text-muted-foreground">کلید متنی (اگر اسکن ممکن نبود)</p>
                <div className="flex items-center gap-1.5">
                  <code dir="ltr" className="flex-1 text-[11px] font-mono bg-secondary border border-border rounded px-2 py-1.5 break-all">
                    {setup.secret}
                  </code>
                  <CopyButton value={setup.secret} />
                </div>
              </div>
            </div>

            <form onSubmit={confirm} className="space-y-2.5">
              <label className="text-[10px] text-muted-foreground">کد شش‌رقمی</label>
              <input value={code} onChange={e => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                inputMode="numeric" autoComplete="one-time-code" placeholder="۱۲۳۴۵۶" dir="ltr"
                className="w-full py-2 px-2 bg-secondary border border-border rounded text-center text-lg font-mono tracking-[0.4em] text-foreground focus:outline-none focus:border-primary/40" />
              <Msg msg={msg} />
              <div className="flex items-center gap-2">
                <button type="submit" disabled={busy || code.length !== 6}
                  className="flex items-center gap-2 py-2 px-3 rounded bg-primary/15 border border-primary/30 text-primary text-xs hover:bg-primary/25 transition-colors disabled:opacity-40">
                  {busy ? <Loader2 size={13} className="animate-spin" /> : <ShieldCheck size={12} />} فعال‌سازی
                </button>
                <button type="button" onClick={() => { setStage("idle"); setSetup(null); setCode(""); setMsg(null); }}
                  className="text-xs text-muted-foreground hover:text-foreground transition-colors">
                  انصراف
                </button>
              </div>
            </form>
          </>
        ) : (
          <>
            <p className="text-[12px] text-muted-foreground leading-relaxed">
              با فعال‌کردن ورود دو عاملی، هنگام ورود علاوه بر رمز عبور یک کد شش‌رقمی از برنامهٔ
              احرازکنندهٔ شما هم خواسته می‌شود. اگر رمز عبورتان جایی فاش شود، حساب همچنان محافظت‌شده می‌ماند.
            </p>
            <Msg msg={msg} />
            <button onClick={begin} disabled={busy}
              className="flex items-center gap-2 py-2 px-3 rounded bg-primary/15 border border-primary/30 text-primary text-xs hover:bg-primary/25 transition-colors disabled:opacity-40">
              {busy ? <Loader2 size={13} className="animate-spin" /> : <Smartphone size={12} />} فعال‌سازی ورود دو عاملی
            </button>
          </>
        )}
      </div>
    </section>
  );
}

// Shown exactly once: the server keeps only hashes, so these cannot be re-read.
function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const text = codes.join("\n");

  const download = () => {
    const blob = new Blob([`کدهای بازیابی افراکاو\n\n${text}\n`], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "afrakav-recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
    setSaved(true);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-start gap-2 text-[11px] text-[#ff8c00] border border-[#ff8c00]/25 bg-[#ff8c00]/5 rounded px-2.5 py-2">
        <AlertTriangle size={12} className="mt-0.5 flex-shrink-0" />
        <p className="leading-relaxed">
          ورود دو عاملی فعال شد. این کدهای بازیابی را همین حالا در جای امنی ذخیره کنید —
          هر کد فقط یک‌بار کار می‌کند و پس از بستن این صفحه دیگر قابل نمایش نیست.
          اگر گوشی خود را از دست بدهید، تنها راه ورود همین کدهاست.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-1.5" dir="ltr">
        {codes.map(c => (
          <code key={c} className="text-[12px] font-mono text-foreground bg-secondary border border-border rounded px-2 py-1.5 text-center">
            {c}
          </code>
        ))}
      </div>

      <div className="flex items-center gap-2">
        <button onClick={download}
          className="flex items-center gap-1.5 py-1.5 px-2.5 rounded border border-border text-xs text-muted-foreground hover:text-primary hover:border-primary/30 transition-colors">
          <Download size={12} /> دانلود
        </button>
        <CopyButton value={text} label="کپی همه" onCopied={() => setSaved(true)} />
        <button onClick={onDone} disabled={!saved}
          className="ms-auto py-1.5 px-3 rounded bg-primary/15 border border-primary/30 text-primary text-xs hover:bg-primary/25 transition-colors disabled:opacity-40"
          title={saved ? "" : "ابتدا کدها را ذخیره یا کپی کنید"}>
          ذخیره کردم
        </button>
      </div>
    </div>
  );
}

// ── password ─────────────────────────────────────────────────────────────────

function PasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (next !== repeat) {
      setMsg({ ok: false, text: "رمز جدید و تکرار آن یکسان نیستند" });
      return;
    }
    setBusy(true); setMsg(null);
    try {
      await changePassword(current, next);
      setMsg({ ok: true, text: "رمز عبور تغییر کرد. سایر نشست‌های شما بسته شدند." });
      setCurrent(""); setNext(""); setRepeat("");
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || "تغییر رمز عبور ناموفق بود" });
    } finally { setBusy(false); }
  };

  return (
    <section className="bg-card border border-border rounded overflow-hidden">
      <div className="px-4 py-3 border-b border-border bg-secondary/20 flex items-center gap-2">
        <KeyRound size={14} className="text-primary" />
        <span className="text-xs font-semibold text-foreground">رمز عبور</span>
      </div>
      <form onSubmit={submit} className="p-4 space-y-2.5">
        <PasswordField label="رمز عبور فعلی" value={current} onChange={setCurrent} />
        <PasswordField label="رمز عبور جدید" value={next} onChange={setNext} placeholder="حداقل ۱۲ نویسه" />
        <PasswordField label="تکرار رمز جدید" value={repeat} onChange={setRepeat} />
        <Msg msg={msg} />
        <button type="submit" disabled={busy || !current || !next || !repeat}
          className="flex items-center gap-2 py-2 px-3 rounded bg-primary/15 border border-primary/30 text-primary text-xs hover:bg-primary/25 transition-colors disabled:opacity-40">
          {busy ? <Loader2 size={13} className="animate-spin" /> : <KeyRound size={12} />} ذخیرهٔ رمز جدید
        </button>
      </form>
    </section>
  );
}

// ── shared bits ──────────────────────────────────────────────────────────────

function PasswordField({ label, value, onChange, placeholder }: {
  label: string; value: string; onChange: (v: string) => void; placeholder?: string;
}) {
  return (
    <div>
      <label className="text-[10px] text-muted-foreground">{label}</label>
      <input type="password" value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} dir="ltr"
        className="mt-1 w-full py-2 px-2 bg-secondary border border-border rounded text-sm font-mono text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40" />
    </div>
  );
}

function CopyButton({ value, label, onCopied }: { value: string; label?: string; onCopied?: () => void }) {
  const [done, setDone] = useState(false);
  const timer = useRef<number | undefined>(undefined);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setDone(true);
      onCopied?.();
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setDone(false), 1500);
    } catch {
      /* clipboard blocked — the value is on screen to copy by hand */
    }
  };

  useEffect(() => () => window.clearTimeout(timer.current), []);

  return (
    <button type="button" onClick={copy} title="کپی"
      className="flex items-center gap-1.5 py-1.5 px-2.5 rounded border border-border text-xs text-muted-foreground hover:text-primary hover:border-primary/30 transition-colors flex-shrink-0">
      {done ? <CheckCircle size={12} className="text-primary" /> : <Copy size={12} />}
      {label && <span>{done ? "کپی شد" : label}</span>}
    </button>
  );
}

function Msg({ msg }: { msg: { ok: boolean; text: string } | null }) {
  if (!msg) return null;
  return (
    <div className={`flex items-start gap-2 text-[11px] rounded px-2.5 py-1.5 border ${
      msg.ok ? "text-primary border-primary/25 bg-primary/5" : "text-[#ff3b3b] border-[#ff3b3b]/25 bg-[#ff3b3b]/5"
    }`}>
      {msg.ok ? <CheckCircle size={12} className="mt-0.5 flex-shrink-0" /> : <AlertTriangle size={12} className="mt-0.5 flex-shrink-0" />}
      <span className="leading-relaxed">{msg.text}</span>
    </div>
  );
}

// window.confirm, named so it does not shadow the component's own `confirm`.
function confirm2(message: string) {
  return window.confirm(message);
}
