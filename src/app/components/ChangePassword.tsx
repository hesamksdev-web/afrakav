import { useState } from "react";
import { KeyRound, Loader2, X, CheckCircle, AlertTriangle } from "lucide-react";
import { changePassword } from "../api";

// Password change is available to every signed-in account. The server voids the
// tokens issued before the change and returns a fresh one, so the session that
// made the change stays open while any other session is signed out.
export default function ChangePassword() {
  const [open, setOpen] = useState(false);

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        title="تغییر رمز عبور"
        className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-primary transition-colors"
      >
        <KeyRound size={13} /> <span className="hidden sm:inline">رمز عبور</span>
      </button>
      {open && <Dialog onClose={() => setOpen(false)} />}
    </>
  );
}

function Dialog({ onClose }: { onClose: () => void }) {
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
    setBusy(true);
    setMsg(null);
    try {
      await changePassword(current, next);
      setMsg({ ok: true, text: "رمز عبور تغییر کرد. سایر نشست‌های شما بسته شدند." });
      setCurrent(""); setNext(""); setRepeat("");
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || "تغییر رمز عبور ناموفق بود" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-sm bg-card border border-border rounded p-4"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 mb-3">
          <KeyRound size={13} className="text-primary" />
          <span className="text-xs font-semibold text-foreground">تغییر رمز عبور</span>
          <button
            type="button"
            onClick={onClose}
            aria-label="بستن"
            className="ms-auto text-muted-foreground hover:text-foreground transition-colors"
          >
            <X size={13} />
          </button>
        </div>

        <form onSubmit={submit} className="space-y-2.5">
          <PasswordField label="رمز عبور فعلی" value={current} onChange={setCurrent} />
          <PasswordField label="رمز عبور جدید" value={next} onChange={setNext} placeholder="حداقل ۱۲ نویسه" />
          <PasswordField label="تکرار رمز جدید" value={repeat} onChange={setRepeat} />

          {msg && (
            <div className={`flex items-center gap-2 text-[11px] rounded px-2.5 py-1.5 border ${
              msg.ok
                ? "text-primary border-primary/25 bg-primary/5"
                : "text-[#ff3b3b] border-[#ff3b3b]/25 bg-[#ff3b3b]/5"
            }`}>
              {msg.ok ? <CheckCircle size={12} /> : <AlertTriangle size={12} />} {msg.text}
            </div>
          )}

          <button
            type="submit"
            disabled={busy || !current || !next || !repeat}
            className="w-full flex items-center justify-center gap-2 py-2 rounded bg-primary/15 border border-primary/30 text-primary text-xs hover:bg-primary/25 transition-colors disabled:opacity-40"
          >
            {busy ? <Loader2 size={13} className="animate-spin" /> : <KeyRound size={12} />} ذخیرهٔ رمز جدید
          </button>
        </form>
      </div>
    </div>
  );
}

function PasswordField({ label, value, onChange, placeholder }: {
  label: string; value: string; onChange: (v: string) => void; placeholder?: string;
}) {
  return (
    <div>
      <label className="text-[10px] text-muted-foreground">{label}</label>
      <input
        type="password"
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        dir="ltr"
        className="mt-1 w-full py-2 px-2 bg-secondary border border-border rounded text-sm font-mono text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40"
      />
    </div>
  );
}
