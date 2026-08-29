import { useEffect, useRef, useState } from "react";
import {
  Shield, LogOut, UserPlus, Upload, Users, Server, FileText,
  Loader2, CheckCircle, AlertTriangle, RefreshCw,
} from "lucide-react";
import { useAuth } from "./auth";
import { Customer, listCustomers, createCustomer, adminUpload } from "./api";
import ThemeToggle from "./components/ThemeToggle";

const faNum = (n: number) => n.toLocaleString("fa-IR");

export default function Admin() {
  const { user, logout } = useAuth();
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = () => {
    setLoading(true);
    listCustomers().then(setCustomers).catch(() => {}).finally(() => setLoading(false));
  };
  useEffect(refresh, []);

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Nav */}
      <nav className="border-b border-border bg-card">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-3">
          <Shield size={16} className="text-primary" />
          <span className="font-mono font-bold text-primary tracking-widest text-sm" dir="ltr">AFRANET</span>
          <span className="text-[10px] text-muted-foreground border-s border-border ps-2">مدیریت</span>
          <div className="ms-auto flex items-center gap-4">
            <span className="text-xs font-mono text-muted-foreground hidden sm:block" dir="ltr">{user?.username}</span>
            <ThemeToggle />
            <button onClick={logout} className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-[#ff3b3b] transition-colors">
              <LogOut size={13} className="-scale-x-100" /> خروج
            </button>
          </div>
        </div>
      </nav>

      <div className="max-w-6xl mx-auto w-full px-4 py-6 grid md:grid-cols-[1fr_1.4fr] gap-6">
        {/* ── Actions column ── */}
        <div className="space-y-6">
          <CreateCustomerCard onCreated={refresh} />
          <UploadCard customers={customers} onUploaded={refresh} />
        </div>

        {/* ── Customers list ── */}
        <div className="bg-card border border-border rounded overflow-hidden">
          <div className="px-4 py-3 border-b border-border bg-secondary/20 flex items-center gap-2">
            <Users size={13} className="text-primary" />
            <span className="text-xs font-semibold text-foreground">
              مشتریان — {faNum(customers.length)}
            </span>
            <button onClick={refresh} className="ms-auto text-muted-foreground hover:text-primary transition-colors">
              <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
            </button>
          </div>

          {loading ? (
            <div className="py-12 flex justify-center text-muted-foreground"><Loader2 size={20} className="animate-spin" /></div>
          ) : customers.length === 0 ? (
            <div className="py-12 text-center text-xs text-muted-foreground">
              هنوز مشتری‌ای ایجاد نشده است.
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-[10px] text-muted-foreground border-b border-border">
                  <th className="text-start px-4 py-2 font-normal">مشتری</th>
                  <th className="text-end px-2 py-2 font-normal">میزبان‌ها</th>
                  <th className="text-end px-2 py-2 font-normal">اسکن‌ها</th>
                  <th className="text-end px-4 py-2 font-normal">آخرین اسکن</th>
                </tr>
              </thead>
              <tbody>
                {customers.map(c => (
                  <tr key={c.id} className="border-b border-border last:border-0 hover:bg-secondary/20">
                    <td className="px-4 py-2.5">
                      <div className="text-foreground font-mono" dir="ltr" style={{ textAlign: "start" }}>{c.username}</div>
                      {c.displayName && <div className="text-[10px] text-muted-foreground">{c.displayName}</div>}
                    </td>
                    <td className="text-end px-2 py-2.5 text-primary">{faNum(c.hostCount)}</td>
                    <td className="text-end px-2 py-2.5 text-muted-foreground">{faNum(c.scanCount)}</td>
                    <td className="text-end px-4 py-2.5 text-muted-foreground">
                      {c.lastScan ? new Date(c.lastScan).toLocaleDateString("fa-IR") : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <footer className="mt-auto border-t border-border py-4 px-4 text-center text-[11px] text-muted-foreground">
        افرانت ® افراشودَن · پنل مدیریت
      </footer>
    </div>
  );
}

// ── Create customer ──────────────────────────────────────────────────────────
function CreateCustomerCard({ onCreated }: { onCreated: () => void }) {
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try {
      await createCustomer(username.trim(), password, displayName.trim());
      setMsg({ ok: true, text: `مشتری «${username}» ایجاد شد.` });
      setUsername(""); setDisplayName(""); setPassword("");
      onCreated();
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || "ایجاد مشتری ناموفق بود" });
    } finally { setBusy(false); }
  };

  return (
    <div className="bg-card border border-border rounded p-4">
      <div className="flex items-center gap-2 mb-3">
        <UserPlus size={13} className="text-primary" />
        <span className="text-xs font-semibold text-foreground">ایجاد مشتری جدید</span>
      </div>
      <form onSubmit={submit} className="space-y-2.5">
        <Field label="نام کاربری" value={username} onChange={setUsername} placeholder="acme-corp" ltr />
        <Field label="نام نمایشی" value={displayName} onChange={setDisplayName} placeholder="شرکت نمونه" />
        <Field label="رمز عبور" value={password} onChange={setPassword} placeholder="حداقل ۶ نویسه" type="password" ltr />
        <Msg msg={msg} />
        <button type="submit" disabled={busy || !username || !password}
          className="w-full flex items-center justify-center gap-2 py-2 rounded bg-primary/15 border border-primary/30 text-primary text-xs hover:bg-primary/25 transition-colors disabled:opacity-40">
          {busy ? <Loader2 size={13} className="animate-spin" /> : <UserPlus size={12} />} ایجاد مشتری
        </button>
      </form>
    </div>
  );
}

// ── Upload & assign ──────────────────────────────────────────────────────────
function UploadCard({ customers, onUploaded }: { customers: Customer[]; onUploaded: () => void }) {
  const [customerId, setCustomerId] = useState<number | "">("");
  const [file, setFile] = useState<File | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file || customerId === "") return;
    setBusy(true); setMsg(null);
    try {
      const res = await adminUpload(file, Number(customerId));
      setMsg({ ok: true, text: `«${res.scan.filename}» پردازش شد — ${faNum(res.hostsParsed)} میزبان.` });
      setFile(null); if (inputRef.current) inputRef.current.value = "";
      onUploaded();
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || "بارگذاری ناموفق بود" });
    } finally { setBusy(false); }
  };

  return (
    <div className="bg-card border border-border rounded p-4">
      <div className="flex items-center gap-2 mb-3">
        <Upload size={13} className="text-primary" />
        <span className="text-xs font-semibold text-foreground">بارگذاری اسکن Nessus</span>
      </div>
      <form onSubmit={submit} className="space-y-2.5">
        <div>
          <label className="text-[10px] text-muted-foreground">تخصیص به مشتری</label>
          <select value={customerId} onChange={e => setCustomerId(e.target.value === "" ? "" : Number(e.target.value))}
            className="mt-1 w-full py-2 px-2 bg-secondary border border-border rounded text-sm text-foreground focus:outline-none focus:border-primary/40">
            <option value="">— انتخاب مشتری —</option>
            {customers.map(c => <option key={c.id} value={c.id}>{c.username}{c.displayName ? ` (${c.displayName})` : ""}</option>)}
          </select>
        </div>

        <div>
          <label className="text-[10px] text-muted-foreground">فایل Nessus <span dir="ltr" className="font-mono">(.nessus)</span></label>
          <button type="button" onClick={() => inputRef.current?.click()}
            className="mt-1 w-full flex items-center gap-2 py-2 px-3 bg-secondary border border-border rounded text-xs text-muted-foreground hover:border-primary/40 transition-colors">
            <FileText size={13} className="text-primary flex-shrink-0" />
            <span className="truncate font-mono" dir="ltr">{file ? file.name : "انتخاب فایل…"}</span>
          </button>
          <input ref={inputRef} type="file" accept=".nessus,.xml" className="hidden"
            onChange={e => setFile(e.target.files?.[0] ?? null)} />
        </div>

        <Msg msg={msg} />
        <button type="submit" disabled={busy || !file || customerId === ""}
          className="w-full flex items-center justify-center gap-2 py-2 rounded bg-primary/15 border border-primary/30 text-primary text-xs hover:bg-primary/25 transition-colors disabled:opacity-40">
          {busy ? <Loader2 size={13} className="animate-spin" /> : <Server size={12} />} بارگذاری و تخصیص
        </button>
      </form>
    </div>
  );
}

// ── small shared bits ────────────────────────────────────────────────────────
function Field({ label, value, onChange, placeholder, type = "text", ltr = false }: {
  label: string; value: string; onChange: (v: string) => void; placeholder?: string; type?: string; ltr?: boolean;
}) {
  return (
    <div>
      <label className="text-[10px] text-muted-foreground">{label}</label>
      <input type={type} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
        dir={ltr ? "ltr" : undefined}
        className={`mt-1 w-full py-2 px-2 bg-secondary border border-border rounded text-sm ${ltr ? "font-mono" : ""} text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40`} />
    </div>
  );
}

function Msg({ msg }: { msg: { ok: boolean; text: string } | null }) {
  if (!msg) return null;
  return (
    <div className={`flex items-center gap-2 text-[11px] rounded px-2.5 py-1.5 border ${
      msg.ok ? "text-primary border-primary/25 bg-primary/5" : "text-[#ff3b3b] border-[#ff3b3b]/25 bg-[#ff3b3b]/5"
    }`}>
      {msg.ok ? <CheckCircle size={12} /> : <AlertTriangle size={12} />} {msg.text}
    </div>
  );
}
