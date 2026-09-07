import { useState } from "react";
import { Shield, Lock, User as UserIcon, Loader2 } from "lucide-react";
import { useAuth } from "./auth";
import ThemeToggle from "./components/ThemeToggle";

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      await login(username.trim(), password);
    } catch (err: any) {
      setError(err?.message || "ورود ناموفق بود");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center px-4">
      <div className="fixed top-4 end-4"><ThemeToggle /></div>
      <div className="w-full max-w-sm">
        {/* Brand */}
        <div className="flex items-center justify-center gap-2 mb-1">
          <Shield size={20} className="text-primary" />
          <span className="font-mono font-bold text-primary tracking-widest text-lg" dir="ltr">AFRANET</span>
          <span className="text-[11px] text-muted-foreground border-s border-border ps-2 ms-1">افراکاو</span>
        </div>
        <p className="text-center text-xs text-muted-foreground mb-8">
          سامانهٔ هوش سطح حمله — ورود مشتریان و مدیران
        </p>

        <form onSubmit={submit} className="bg-card border border-border rounded p-6 space-y-4">
          <div>
            <label className="text-[11px] text-muted-foreground">نام کاربری</label>
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
            <label className="text-[11px] text-muted-foreground">رمز عبور</label>
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

        <p className="text-center text-[11px] text-muted-foreground mt-6">
          حساب کاربری شما توسط مدیر افرانت برایتان ایجاد می‌شود.
        </p>
      </div>
    </div>
  );
}
