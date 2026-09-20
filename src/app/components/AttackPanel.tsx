import { useEffect, useState } from "react";
import { ChevronDown, ExternalLink, Loader2, Crosshair, Info } from "lucide-react";
import { AttackSource, AttackTechnique, HostAttack, fetchHostAttack } from "../api";
import { faNum } from "../format";
import { SEV_COLOR, SEV_FA } from "./severity";

const SOURCE_FA: Record<AttackSource, { label: string; title: string; cls: string }> = {
  weakness: {
    label: "بر پایهٔ CWE",
    title: "از ردهٔ ضعف (CWE) خودِ یافته به دست آمده است",
    cls: "text-primary border-primary/30 bg-primary/5",
  },
  rule: {
    label: "استنباطی",
    title: "بر پایهٔ قواعد افراکاو دربارهٔ این پلاگین است، نه نگاشت رسمی MITRE",
    cls: "text-[#ff8c00] border-[#ff8c00]/30 bg-[#ff8c00]/5",
  },
};

/**
 * MITRE ATT&CK for one host: what an attacker could do with what is wrong
 * here.
 *
 * Two things this panel refuses to hide. First, where each mapping came from —
 * a CWE-derived technique and one of our own plugin rules are not the same
 * claim, so they carry different badges. Second, how many findings mapped to
 * nothing: a technique list read without that number looks like full coverage
 * when it is usually partial.
 */
export default function AttackPanel({ host, customerId }: {
  host: string;
  customerId?: number;
}) {
  const [data, setData] = useState<HostAttack | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setFailed(false);
    fetchHostAttack(host, customerId)
      .then(res => { if (!cancelled) setData(res); })
      .catch(() => { if (!cancelled) setFailed(true); });
    return () => { cancelled = true; };
  }, [host, customerId]);

  if (failed) return null;

  return (
    <section className="bg-card border border-border rounded overflow-hidden">
      <div className="px-4 py-3 border-b border-border bg-secondary/20 flex items-center gap-2 flex-wrap">
        <Crosshair size={13} className="text-primary" />
        <span className="text-xs font-semibold text-foreground">
          تکنیک‌های <span dir="ltr" className="font-mono">MITRE ATT&CK</span>
        </span>
        {data && (
          <span className="ms-auto text-[11px] text-muted-foreground">
            {faNum(data.mappedFindings)} از {faNum(data.totalFindings)} یافته نگاشت شد
          </span>
        )}
      </div>

      {!data ? (
        <div className="py-10 flex justify-center text-muted-foreground">
          <Loader2 size={18} className="animate-spin" />
        </div>
      ) : data.techniques.length === 0 ? (
        <p className="px-4 py-8 text-center text-[12px] text-muted-foreground leading-relaxed">
          {data.totalFindings === 0
            ? "این میزبان یافته‌ای ندارد، پس تکنیکی هم برایش نگاشت نمی‌شود."
            : "هیچ‌کدام از یافته‌های این میزبان به تکنیک شناخته‌شده‌ای نگاشت نشد."}
        </p>
      ) : (
        <div className="divide-y divide-border">
          {data.techniques.map(t => <TechniqueRow key={t.id} technique={t} />)}
        </div>
      )}

      {data && data.unmappedFindings > 0 && (
        <p className="px-4 py-2.5 border-t border-border text-[11px] text-muted-foreground">
          {faNum(data.unmappedFindings)} یافته به هیچ تکنیکی نگاشت نشد.
        </p>
      )}

      <div className="px-4 py-3 border-t border-border bg-secondary/10 flex items-start gap-2">
        <Info size={11} className="text-muted-foreground flex-shrink-0 mt-0.5" />
        <p className="text-[11px] text-muted-foreground leading-relaxed">
          این فهرست می‌گوید مهاجم با این ضعف‌ها <span className="text-foreground">چه می‌تواند بکند</span>،
          نه اینکه حمله عملی و تأییدشده است. میزان در معرض بودن میزبان (مثلاً دسترس‌پذیری از اینترنت)
          در فایل اسکن ثبت نمی‌شود و در این نگاشت لحاظ نشده است.
        </p>
      </div>
    </section>
  );
}

function TechniqueRow({ technique }: { technique: AttackTechnique }) {
  const [open, setOpen] = useState(false);

  return (
    <div>
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full text-start px-4 py-3 hover:bg-secondary/20 transition-colors flex items-start gap-3"
      >
        <span className="font-mono text-[12px] text-primary flex-shrink-0 pt-0.5" dir="ltr">
          {technique.id}
        </span>

        <span className="flex-1 min-w-0">
          <span className="block text-[13px] text-foreground" dir="ltr" style={{ textAlign: "start" }}>
            {technique.name}
          </span>
          <span className="flex flex-wrap items-center gap-1.5 mt-1.5">
            {technique.tactics.map(tac => (
              <span key={tac} dir="ltr"
                className="text-[10px] text-muted-foreground border border-border rounded px-1.5 py-0.5">
                {tac}
              </span>
            ))}
            {technique.sources.map(s => (
              <span key={s} title={SOURCE_FA[s].title}
                className={`text-[10px] rounded px-1.5 py-0.5 border ${SOURCE_FA[s].cls}`}>
                {SOURCE_FA[s].label}
              </span>
            ))}
          </span>
        </span>

        <span className="flex items-center gap-2 flex-shrink-0 text-muted-foreground pt-0.5">
          <span className="text-[11px]">{faNum(technique.findings.length)} یافته</span>
          <ChevronDown size={12} className={`transition-transform ${open ? "rotate-180" : ""}`} />
        </span>
      </button>

      {open && (
        <div className="px-4 pb-3.5 space-y-2.5 bg-secondary/10">
          {technique.reasons.length > 0 && (
            <p className="text-[11px] text-muted-foreground pt-2.5">
              دلیل نگاشت: {technique.reasons.join(" · ")}
            </p>
          )}

          <ul className="space-y-1.5">
            {technique.findings.map(f => (
              <li key={`${f.pluginId}-${f.name}`} className="flex items-start gap-2 text-[12px]">
                <span className="w-1.5 h-1.5 rounded-sm flex-shrink-0 mt-1.5"
                      style={{ background: SEV_COLOR[f.severity] }} />
                <span className="flex-1 min-w-0">
                  <span className="text-foreground" dir="ltr" style={{ textAlign: "start", display: "block" }}>
                    {f.name}
                  </span>
                  <span className="text-[11px] text-muted-foreground">
                    {SEV_FA[f.severity]}
                    {f.cve && <> · <span className="font-mono" dir="ltr">{f.cve}</span></>}
                  </span>
                </span>
              </li>
            ))}
          </ul>

          <a href={technique.url} target="_blank" rel="noreferrer"
             className="inline-flex items-center gap-1 text-[11px] text-primary hover:underline">
            <ExternalLink size={9} /> توضیح این تکنیک در MITRE
          </a>
        </div>
      )}
    </div>
  );
}
