import { useState } from "react";
import { Lock, User as UserIcon, Loader2, ShieldCheck, ArrowRight } from "lucide-react";
import { useAuth } from "./auth";
import Brand from "./components/Brand";
import ThemeToggle from "./components/ThemeToggle";
import AccessRequest from "./AccessRequest";

export default function Login() {
  const { login, verifyCode } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  // Set when the password was right but the account also needs a second factor.
  // It is not a session token — it only carries this attempt to the next step.
  const [challenge, setChallenge] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [requesting, setRequesting] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      const result = await login(username.trim(), password);
      if (result.kind === "needs-code") {
        setChallenge(result.challenge);
        setPassword("");
      }
    } catch (err: any) {
      setError(err?.message || "ورود ناموفق بود");
    } finally {
      setBusy(false);
    }
  };

  const submitCode = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      await verifyCode(challenge!, code.trim());
    } catch (err: any) {
      setError(err?.message || "کد تأیید پذیرفته نشد");
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  const startOver = () => {
    setChallenge(null); setCode(""); setError(""); setPassword("");
  };

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center px-4">
      <div className="fixed top-4 end-4"><ThemeToggle /></div>
      <div className="w-full max-w-sm">
        {/* Brand */}
        {/* The mark carries the brand on its own here; stacking the product
            name under it reads better than crowding both onto one line. */}
        <div className="flex flex-col items-center gap-3 mb-8">
          <Brand className="h-9" />
          <div className="flex flex-col items-center gap-1">
            <h1 className="text-base font-bold text-foreground tracking-tight">افراکاو</h1>
            <p className="text-[12px] text-muted-foreground">سامانهٔ مدیریت آسیب‌پذیری</p>
          </div>
        </div>

        {requesting ? (
          <AccessRequest onBack={() => setRequesting(false)} />
        ) : challenge ? (
          <form onSubmit={submitCode} className="bg-card border border-border rounded p-6 space-y-4">
            <div className="flex items-center gap-2">
              <ShieldCheck size={15} className="text-primary" />
              <span className="text-sm font-semibold text-foreground">تأیید دو مرحله‌ای</span>
            </div>
            <p className="text-[12px] text-muted-foreground leading-relaxed">
              کد شش‌رقمی برنامهٔ احرازکنندهٔ خود را وارد کنید. اگر به آن دسترسی ندارید،
              می‌توانید یکی از کدهای بازیابی را بنویسید.
            </p>

            <input
              autoFocus value={code}
              onChange={e => setCode(e.target.value.replace(/[^0-9a-fA-F-]/g, "").slice(0, 19))}
              inputMode="numeric" autoComplete="one-time-code" placeholder="۱۲۳۴۵۶" dir="ltr"
              className="w-full py-2.5 px-2 bg-secondary border border-border rounded text-center text-lg font-mono tracking-[0.3em] text-foreground focus:outline-none focus:border-primary/40"
            />

            {error && (
              <div className="text-xs text-[#ff3b3b] border border-[#ff3b3b]/25 bg-[#ff3b3b]/5 rounded px-3 py-2">
                {error}
              </div>
            )}

            <button
              type="submit" disabled={busy || code.length < 6}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded bg-primary/15 border border-primary/30 text-primary text-sm hover:bg-primary/25 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {busy ? <Loader2 size={14} className="animate-spin" /> : <ShieldCheck size={13} />}
              {busy ? "در حال بررسی…" : "تأیید و ورود"}
            </button>

            <button type="button" onClick={startOver}
              className="w-full flex items-center justify-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground transition-colors">
              <ArrowRight size={11} /> بازگشت و ورود با حساب دیگر
            </button>
          </form>
        ) : (
        <form onSubmit={submit} className="bg-card border border-border rounded p-6 space-y-4">
          <div>
            <label className="text-[12px] text-muted-foreground">نام کاربری</label>
            <div className="mt-1 flex items-center bg-secondary border border-border rounded overflow-hidden focus-within:border-primary/40 transition-colors">
              <span className="px-3 text-muted-foreground"><UserIcon size={14} /></span>
              <input
                autoFocus value={username} onChange={e => setUsername(e.target.value)}
                dir="ltr"
                className="flex-1 py-2.5 bg-transparent text-sm font-mono text-foreground focus:outline-none"
                placeholder="username"
              />
            </div>
          </div>

          <div>
            <label className="text-[12px] text-muted-foreground">رمز عبور</label>
            <div className="mt-1 flex items-center bg-secondary border border-border rounded overflow-hidden focus-within:border-primary/40 transition-colors">
              <span className="px-3 text-muted-foreground"><Lock size={14} /></span>
              <input
                type="password" value={password} onChange={e => setPassword(e.target.value)}
                dir="ltr"
                className="flex-1 py-2.5 bg-transparent text-sm font-mono text-foreground focus:outline-none"
                placeholder="••••••••"
              />
            </div>
          </div>

          {error && (
            <div className="text-xs text-[#ff3b3b] border border-[#ff3b3b]/25 bg-[#ff3b3b]/5 rounded px-3 py-2">
              {error}
            </div>
          )}

          <button
            type="submit" disabled={busy || !username || !password}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded bg-primary/15 border border-primary/30 text-primary text-sm hover:bg-primary/25 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Lock size={13} />}
            {busy ? "در حال ورود…" : "ورود"}
          </button>
        </form>
        )}

        {!requesting && !challenge && (
          <p className="text-center text-[12px] text-muted-foreground mt-6">
            هنوز حساب کاربری ندارید؟{" "}
            <button onClick={() => { setRequesting(true); setError(""); }}
              className="text-primary hover:underline">
              درخواست دسترسی
            </button>
          </p>
        )}
      </div>
    </div>
  );
}
