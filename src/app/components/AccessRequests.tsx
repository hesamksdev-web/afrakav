import { useEffect, useState } from "react";
import {
  Inbox, Loader2, CheckCircle, AlertTriangle, UserPlus, X, ChevronDown, ChevronUp,
} from "lucide-react";
import {
  AccessRequest, listAccessRequests, approveAccessRequest, rejectAccessRequest,
} from "../api";

const faNum = (n: number) => n.toLocaleString("fa-IR");
const faDate = (iso: string) => new Date(iso).toLocaleDateString("fa-IR");

const STATUS_FA: Record<AccessRequest["status"], string> = {
  pending: "در انتظار بررسی", approved: "تأیید شده", rejected: "رد شده",
};

/**
 * Sign-up requests from the public login form. Nothing here is a credential:
 * approving opens a form where the admin picks the username and password, so a
 * visitor cannot influence the account they end up with beyond suggesting a name.
 */
export default function AccessRequests({ onApproved }: { onApproved: () => void }) {
  const [filter, setFilter] = useState<AccessRequest["status"] | "all">("pending");
  const [items, setItems] = useState<AccessRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = () => {
    setLoading(true);
    listAccessRequests(filter === "all" ? undefined : filter)
      .then(setItems)
      .catch(err => setError(err?.message || "بارگیری درخواست‌ها ناموفق بود"))
      .finally(() => setLoading(false));
  };
  useEffect(refresh, [filter]);

  const pendingCount = items.filter(i => i.status === "pending").length;

  return (
    <section className="bg-card border border-border rounded overflow-hidden">
      <div className="px-4 py-3 border-b border-border bg-secondary/20 flex items-center gap-2 flex-wrap">
        <Inbox size={13} className="text-primary" />
        <span className="text-xs font-semibold text-foreground">درخواست‌های دسترسی</span>
        {filter === "pending" && pendingCount > 0 && (
          <span className="text-[10px] text-[#ff8c00] border border-[#ff8c00]/30 bg-[#ff8c00]/5 rounded px-1.5 py-0.5">
            {faNum(pendingCount)} در انتظار
          </span>
        )}
        <div className="ms-auto flex items-center gap-1">
          {([
            ["pending", "در انتظار"], ["approved", "تأیید شده"],
            ["rejected", "رد شده"], ["all", "همه"],
          ] as const).map(([value, label]) => (
            <button key={value} onClick={() => setFilter(value)}
              className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
                filter === value
                  ? "bg-primary/10 border-primary/30 text-primary"
                  : "border-border text-muted-foreground hover:text-foreground hover:bg-secondary"
              }`}>
              {label}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="py-10 flex justify-center text-muted-foreground"><Loader2 size={18} className="animate-spin" /></div>
      ) : error ? (
        <p className="px-4 py-6 text-center text-[11px] text-[#ff3b3b]">{error}</p>
      ) : items.length === 0 ? (
        <p className="px-4 py-8 text-center text-[11px] text-muted-foreground">
          {filter === "pending" ? "درخواست بررسی‌نشده‌ای وجود ندارد." : "موردی یافت نشد."}
        </p>
      ) : (
        <div className="divide-y divide-border">
          {items.map(item => (
            <RequestRow key={item.id} item={item}
              onChanged={() => { refresh(); onApproved(); }} />
          ))}
        </div>
      )}
    </section>
  );
}

function RequestRow({ item, onChanged }: { item: AccessRequest; onChanged: () => void }) {
  const [open, setOpen] = useState(false);
  const [approving, setApproving] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [username, setUsername] = useState(item.wantedUsername);
  const [password, setPassword] = useState("");

  const approve = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try {
      await approveAccessRequest(item.id, username.trim(), password, item.companyName);
      setMsg({ ok: true, text: `حساب «${username}» ایجاد شد.` });
      setPassword("");
      setApproving(false);
      onChanged();
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || "ایجاد حساب ناموفق بود" });
    } finally { setBusy(false); }
  };

  const reject = async () => {
    if (!window.confirm(`درخواست «${item.companyName}» رد شود؟`)) return;
    setBusy(true); setMsg(null);
    try {
      await rejectAccessRequest(item.id);
      onChanged();
    } catch (err: any) {
      setMsg({ ok: false, text: err?.message || "رد درخواست ناموفق بود" });
    } finally { setBusy(false); }
  };

  return (
    <div className="px-4 py-3">
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-center gap-2 text-start">
        <span className="text-xs text-foreground truncate">{item.companyName}</span>
        <StatusChip status={item.status} />
        <span className="ms-auto text-[10px] text-muted-foreground flex-shrink-0">{faDate(item.createdAt)}</span>
        {open ? <ChevronUp size={12} className="text-muted-foreground flex-shrink-0" />
              : <ChevronDown size={12} className="text-muted-foreground flex-shrink-0" />}
      </button>

      {open && (
        <div className="mt-3 space-y-3">
          <dl className="grid sm:grid-cols-2 gap-x-4 gap-y-1.5 text-[11px]">
            <Detail label="رابط" value={item.contactName} />
            <Detail label="ایمیل" value={item.email} ltr />
            <Detail label="تماس" value={item.phone} ltr />
            <Detail label="نام کاربری پیشنهادی" value={item.wantedUsername || "—"} ltr />
            <Detail label="نشانی ثبت‌کننده" value={item.sourceIp || "—"} ltr />
            {item.reviewedBy && <Detail label="بررسی‌شده توسط" value={item.reviewedBy} ltr />}
          </dl>

          {item.note && (
            <div>
              <p className="text-[10px] text-muted-foreground mb-1">توضیحات</p>
              <p className="text-[11px] text-foreground leading-relaxed bg-secondary/40 border border-border rounded px-2.5 py-2 whitespace-pre-wrap">
                {item.note}
              </p>
            </div>
          )}

          {msg && (
            <div className={`flex items-start gap-2 text-[11px] rounded px-2.5 py-1.5 border ${
              msg.ok ? "text-primary border-primary/25 bg-primary/5" : "text-[#ff3b3b] border-[#ff3b3b]/25 bg-[#ff3b3b]/5"
            }`}>
              {msg.ok ? <CheckCircle size={12} className="mt-0.5 flex-shrink-0" /> : <AlertTriangle size={12} className="mt-0.5 flex-shrink-0" />}
              <span className="leading-relaxed">{msg.text}</span>
            </div>
          )}

          {item.status === "pending" && !approving && (
            <div className="flex items-center gap-2">
              <button onClick={() => setApproving(true)} disabled={busy}
                className="flex items-center gap-1.5 py-1.5 px-2.5 rounded bg-primary/15 border border-primary/30 text-primary text-[11px] hover:bg-primary/25 transition-colors disabled:opacity-40">
                <UserPlus size={11} /> تأیید و ایجاد حساب
              </button>
              <button onClick={reject} disabled={busy}
                className="flex items-center gap-1.5 py-1.5 px-2.5 rounded border border-border text-[11px] text-muted-foreground hover:text-[#ff3b3b] hover:border-[#ff3b3b]/30 transition-colors disabled:opacity-40">
                {busy ? <Loader2 size={11} className="animate-spin" /> : <X size={11} />} رد درخواست
              </button>
            </div>
          )}

          {approving && (
            <form onSubmit={approve} className="space-y-2 bg-secondary/30 border border-border rounded p-3">
              <p className="text-[10px] text-muted-foreground">
                نام کاربری و رمز عبور را شما تعیین می‌کنید؛ سپس آن را از کانالی امن به مشتری بدهید.
              </p>
              <div className="grid sm:grid-cols-2 gap-2">
                <div>
                  <label className="text-[10px] text-muted-foreground">نام کاربری</label>
                  <input value={username} onChange={e => setUsername(e.target.value)} dir="ltr" placeholder="acme-corp"
                    className="mt-1 w-full py-1.5 px-2 bg-secondary border border-border rounded text-[12px] font-mono text-foreground focus:outline-none focus:border-primary/40" />
                </div>
                <div>
                  <label className="text-[10px] text-muted-foreground">رمز عبور</label>
                  <input type="password" value={password} onChange={e => setPassword(e.target.value)} dir="ltr"
                    placeholder="حداقل ۱۲ نویسه"
                    className="mt-1 w-full py-1.5 px-2 bg-secondary border border-border rounded text-[12px] font-mono text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40" />
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button type="submit" disabled={busy || !username || !password}
                  className="flex items-center gap-1.5 py-1.5 px-2.5 rounded bg-primary/15 border border-primary/30 text-primary text-[11px] hover:bg-primary/25 transition-colors disabled:opacity-40">
                  {busy ? <Loader2 size={11} className="animate-spin" /> : <UserPlus size={11} />} ایجاد حساب
                </button>
                <button type="button" onClick={() => { setApproving(false); setMsg(null); }}
                  className="text-[11px] text-muted-foreground hover:text-foreground transition-colors">
                  انصراف
                </button>
              </div>
            </form>
          )}
        </div>
      )}
    </div>
  );
}

function StatusChip({ status }: { status: AccessRequest["status"] }) {
  const cls = status === "pending" ? "text-[#ff8c00] border-[#ff8c00]/30 bg-[#ff8c00]/5"
            : status === "approved" ? "text-primary border-primary/30 bg-primary/5"
            : "text-muted-foreground border-border";
  return (
    <span className={`text-[9px] rounded px-1.5 py-0.5 border flex-shrink-0 ${cls}`}>
      {STATUS_FA[status]}
    </span>
  );
}

function Detail({ label, value, ltr = false }: { label: string; value: string; ltr?: boolean }) {
  return (
    <div className="flex items-baseline gap-2">
      <dt className="text-muted-foreground flex-shrink-0">{label}</dt>
      <dd className={`text-foreground truncate ${ltr ? "font-mono" : ""}`} dir={ltr ? "ltr" : undefined}
          style={ltr ? { textAlign: "start" } : undefined}>
        {value}
      </dd>
    </div>
  );
}
