import { useState } from "react";
import { Loader2, CheckCircle, AlertTriangle, ArrowRight, Send } from "lucide-react";
import { submitAccessRequest } from "./api";

// The public sign-up form on the login page. It creates nothing: an admin reads
// the request and issues the account separately, so nothing typed here becomes
// a credential.
export default function AccessRequest({ onBack }: { onBack: () => void }) {
  const [form, setForm] = useState({
    companyName: "", contactName: "", email: "", phone: "", wantedUsername: "", note: "",
  });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);

  const set = (key: keyof typeof form) => (v: string) => setForm(f => ({ ...f, [key]: v }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      await submitAccessRequest(form);
      setSent(true);
    } catch (err: any) {
      setError(err?.message || "ثبت درخواست ناموفق بود");
    } finally {
      setBusy(false);
    }
  };

  if (sent) {
    return (
      <div className="bg-card border border-border rounded p-6 space-y-4 text-center">
        <CheckCircle size={28} className="text-primary mx-auto" />
        <div className="space-y-1.5">
          <p className="text-sm font-semibold text-foreground">درخواست شما ثبت شد</p>
          <p className="text-[11px] text-muted-foreground leading-relaxed">
            کارشناسان افرانت درخواست را بررسی می‌کنند و در صورت تأیید، اطلاعات ورود
            از طریق همان ایمیل یا شمارهٔ تماسی که وارد کردید برایتان ارسال می‌شود.
          </p>
        </div>
        <button onClick={onBack}
          className="w-full flex items-center justify-center gap-1.5 py-2 rounded border border-border text-xs text-muted-foreground hover:text-primary hover:border-primary/30 transition-colors">
          <ArrowRight size={12} /> بازگشت به صفحهٔ ورود
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="bg-card border border-border rounded p-6 space-y-3">
      <div className="space-y-1">
        <p className="text-sm font-semibold text-foreground">درخواست دسترسی</p>
        <p className="text-[11px] text-muted-foreground leading-relaxed">
          مشخصات سازمان خود را وارد کنید. پس از بررسی و تأیید، حساب کاربری برایتان
          ایجاد و اطلاعات ورود ارسال می‌شود.
        </p>
      </div>

      <Field label="نام سازمان" value={form.companyName} onChange={set("companyName")}
             placeholder="شرکت نمونه" required />
      <Field label="نام و نام خانوادگی رابط" value={form.contactName} onChange={set("contactName")}
             placeholder="نام رابط فنی یا امنیتی" required />
      <Field label="ایمیل سازمانی" value={form.email} onChange={set("email")}
             placeholder="ops@example.com" type="email" ltr required />
      <Field label="شمارهٔ تماس" value={form.phone} onChange={set("phone")}
             placeholder="۰۲۱-۱۲۳۴۵۶۷۸" ltr required />
      <Field label="نام کاربری پیشنهادی (اختیاری)" value={form.wantedUsername} onChange={set("wantedUsername")}
             placeholder="acme-corp" ltr />

      <div>
        <label className="text-[11px] text-muted-foreground">توضیحات (اختیاری)</label>
        <textarea
          value={form.note} onChange={e => setForm(f => ({ ...f, note: e.target.value.slice(0, 1000) }))}
          rows={3} placeholder="مثلاً تعداد و محدودهٔ آی‌پی‌هایی که می‌خواهید پایش شوند"
          className="mt-1 w-full py-2 px-2 bg-secondary border border-border rounded text-xs text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40 resize-y"
        />
      </div>

      {error && (
        <div className="flex items-start gap-2 text-xs text-[#ff3b3b] border border-[#ff3b3b]/25 bg-[#ff3b3b]/5 rounded px-3 py-2">
          <AlertTriangle size={12} className="mt-0.5 flex-shrink-0" />
          <span className="leading-relaxed">{error}</span>
        </div>
      )}

      <button type="submit"
        disabled={busy || !form.companyName || !form.contactName || !form.email || !form.phone}
        className="w-full flex items-center justify-center gap-2 py-2.5 rounded bg-primary/15 border border-primary/30 text-primary text-sm hover:bg-primary/25 transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
        {busy ? <Loader2 size={14} className="animate-spin" /> : <Send size={13} />}
        {busy ? "در حال ارسال…" : "ارسال درخواست"}
      </button>

      <button type="button" onClick={onBack}
        className="w-full flex items-center justify-center gap-1.5 text-[11px] text-muted-foreground hover:text-foreground transition-colors">
        <ArrowRight size={11} /> بازگشت به صفحهٔ ورود
      </button>
    </form>
  );
}

function Field({ label, value, onChange, placeholder, type = "text", ltr = false, required = false }: {
  label: string; value: string; onChange: (v: string) => void;
  placeholder?: string; type?: string; ltr?: boolean; required?: boolean;
}) {
  return (
    <div>
      <label className="text-[11px] text-muted-foreground">
        {label}{required && <span className="text-[#ff3b3b]"> *</span>}
      </label>
      <input
        type={type} value={value} onChange={e => onChange(e.target.value)}
        placeholder={placeholder} dir={ltr ? "ltr" : undefined}
        className={`mt-1 w-full py-2 px-2 bg-secondary border border-border rounded text-sm ${ltr ? "font-mono" : ""} text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40`}
      />
    </div>
  );
}
