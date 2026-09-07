import { Fragment, useEffect, useState } from "react";
import { ShieldAlert, RefreshCw, Loader2, ChevronDown, Filter } from "lucide-react";
import { AuditEvent, EventFilter, EVENT_ACTION_FA, EVENT_OUTCOME_FA, listAuditEvents } from "../api";

const faNum = (n: number) => n.toLocaleString("fa-IR");

const OUTCOME_STYLE: Record<string, string> = {
  success: "text-primary border-primary/30 bg-primary/5",
  failure: "text-[#ff3b3b] border-[#ff3b3b]/30 bg-[#ff3b3b]/5",
  denied: "text-[#ff8c00] border-[#ff8c00]/30 bg-[#ff8c00]/5",
};

// Admin panel view of the security event log: every login, logout, admin
// action and tenant-data view, filterable and paginated. This is the record
// an incident review would start from, so it stays close to the raw event
// shape rather than summarising it away.
export default function EventsPanel() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [filter, setFilter] = useState<EventFilter>({});
  const [cursors, setCursors] = useState<number[]>([]); // history of previous page starts

  const load = (f: EventFilter) => {
    setLoading(true);
    listAuditEvents(f)
      .then(res => setEvents(res.events))
      .catch(() => setEvents([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(filter); }, [filter.action, filter.outcome, filter.actor, filter.cursor]);

  const applyFilter = (patch: Partial<EventFilter>) => {
    setCursors([]);
    setFilter(f => ({ ...f, ...patch, cursor: undefined }));
  };

  const nextPage = () => {
    if (events.length === 0) return;
    const last = events[events.length - 1].id;
    setCursors(cs => [...cs, filter.cursor ?? Infinity]);
    setFilter(f => ({ ...f, cursor: last }));
  };

  const prevPage = () => {
    setCursors(cs => {
      const copy = [...cs];
      const prev = copy.pop();
      setFilter(f => ({ ...f, cursor: prev === Infinity ? undefined : prev }));
      return copy;
    });
  };

  return (
    <section className="bg-card border border-border rounded overflow-hidden">
      <div className="px-4 py-3 border-b border-border bg-secondary/20 flex items-center gap-2 flex-wrap">
        <ShieldAlert size={13} className="text-primary" />
        <span className="text-xs font-semibold text-foreground">رویدادها</span>
        <span className="text-[11px] text-muted-foreground">ثبت ورود، خروج و اقدامات مدیریتی</span>
        <button onClick={() => load(filter)} className="ms-auto text-muted-foreground hover:text-primary transition-colors">
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
        </button>
      </div>

      <div className="px-4 py-2.5 border-b border-border flex flex-wrap items-center gap-2 bg-secondary/10">
        <Filter size={11} className="text-muted-foreground" />
        <select value={filter.outcome ?? ""} onChange={e => applyFilter({ outcome: e.target.value || undefined })}
          className="py-1 px-2 bg-secondary border border-border rounded text-[11px] text-foreground focus:outline-none focus:border-primary/40">
          <option value="">همهٔ نتیجه‌ها</option>
          <option value="success">موفق</option>
          <option value="failure">ناموفق</option>
          <option value="denied">رد شد</option>
        </select>
        <select value={filter.action ?? ""} onChange={e => applyFilter({ action: e.target.value || undefined })}
          className="py-1 px-2 bg-secondary border border-border rounded text-[11px] text-foreground focus:outline-none focus:border-primary/40 max-w-[200px]">
          <option value="">همهٔ رویدادها</option>
          {Object.entries(EVENT_ACTION_FA).map(([k, label]) => (
            <option key={k} value={k}>{label}</option>
          ))}
        </select>
        <input placeholder="جست‌وجوی کاربر…" dir="ltr" value={filter.actor ?? ""}
          onChange={e => applyFilter({ actor: e.target.value || undefined })}
          className="py-1 px-2 bg-secondary border border-border rounded text-[11px] font-mono text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40 w-36" />
      </div>

      {loading ? (
        <div className="py-12 flex justify-center text-muted-foreground"><Loader2 size={20} className="animate-spin" /></div>
      ) : events.length === 0 ? (
        <div className="py-12 text-center text-xs text-muted-foreground">رویدادی یافت نشد.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-[11px] text-muted-foreground border-b border-border">
                <th className="text-start px-4 py-2 font-normal">زمان</th>
                <th className="text-start px-2 py-2 font-normal">رویداد</th>
                <th className="text-start px-2 py-2 font-normal">کاربر</th>
                <th className="text-start px-2 py-2 font-normal">هدف</th>
                <th className="text-end px-2 py-2 font-normal">نتیجه</th>
                <th className="text-end px-4 py-2 font-normal">IP</th>
              </tr>
            </thead>
            <tbody>
              {events.map(e => (
                <Fragment key={e.id}>
                  <tr onClick={() => setExpanded(x => x === e.id ? null : e.id)}
                    className="border-b border-border last:border-0 hover:bg-secondary/20 cursor-pointer">
                    <td className="px-4 py-2 text-muted-foreground whitespace-nowrap" dir="ltr">
                      {new Date(e.occurredAt).toLocaleString("fa-IR")}
                    </td>
                    <td className="px-2 py-2 text-foreground whitespace-nowrap">
                      {EVENT_ACTION_FA[e.action] ?? e.action}
                    </td>
                    <td className="px-2 py-2 font-mono text-muted-foreground" dir="ltr">
                      {e.actorUsername || "—"}
                    </td>
                    <td className="px-2 py-2 text-muted-foreground truncate max-w-[160px]">
                      {e.targetLabel || (e.targetType ? `${e.targetType}#${e.targetId}` : "—")}
                    </td>
                    <td className="text-end px-2 py-2">
                      <span className={`text-[10px] rounded px-1.5 py-0.5 border ${OUTCOME_STYLE[e.outcome] ?? ""}`}>
                        {EVENT_OUTCOME_FA[e.outcome] ?? e.outcome}
                      </span>
                    </td>
                    <td className="text-end px-4 py-2 font-mono text-muted-foreground whitespace-nowrap" dir="ltr">
                      {e.ip || "—"}
                      <ChevronDown size={11} className={`inline-block ms-1.5 transition-transform ${expanded === e.id ? "rotate-180" : ""}`} />
                    </td>
                  </tr>
                  {expanded === e.id && (
                    <tr className="border-b border-border bg-secondary/10">
                      <td colSpan={6} className="px-4 py-2.5">
                        <pre dir="ltr" className="text-[11px] font-mono text-muted-foreground whitespace-pre-wrap break-all">
{JSON.stringify({ userAgent: e.userAgent, ...e.details }, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="px-4 py-2.5 border-t border-border flex items-center justify-between text-[11px] text-muted-foreground">
        <button onClick={prevPage} disabled={cursors.length === 0}
          className="hover:text-primary transition-colors disabled:opacity-30">صفحهٔ قبل</button>
        <span>{faNum(events.length)} رویداد نمایش‌داده‌شده</span>
        <button onClick={nextPage} disabled={events.length < 200}
          className="hover:text-primary transition-colors disabled:opacity-30">صفحهٔ بعد</button>
      </div>
    </section>
  );
}
