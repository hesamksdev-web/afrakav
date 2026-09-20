import { EstateSnapshot, Severity } from "../api";
import { faNum, faDate } from "../format";
import { SEV_COLOR, SEV_FA } from "./severity";

// Worst on top, so a growing red cap is visible at a glance.
const SERIES: Severity[] = ["Critical", "High", "Medium", "Low"];

const shortDate = (iso: string) =>
  new Date(iso).toLocaleDateString("fa-IR", { month: "numeric", day: "numeric" });

/**
 * Open findings by severity at each scan — the "are we actually improving?"
 * chart.
 *
 * Each column is the state of the WHOLE estate right after that scan, not the
 * contents of the uploaded file, so a scan covering part of the network does
 * not make the trend dip. Host coverage rides in the tooltip rather than a
 * second axis: two scales on one plot invent a relationship the data does not
 * have.
 */
export default function TrendChart({ points }: { points: EstateSnapshot[] }) {
  // Two points is the minimum that can show a direction.
  if (points.length < 2) {
    return (
      <p className="text-[12px] text-muted-foreground leading-relaxed">
        برای نمایش روند، دست‌کم دو اسکن لازم است. پس از اسکن بعدی، تغییر آسیب‌پذیری‌های
        شبکهٔ شما در همین بخش نمایش داده می‌شود.
      </p>
    );
  }

  const shown = points.slice(-12);
  const totalOf = (p: EstateSnapshot) => p.critical + p.high + p.medium + p.low;
  const max = Math.max(...shown.map(totalOf), 1);

  const first = totalOf(shown[0]);
  const last = totalOf(shown[shown.length - 1]);
  const change = last - first;

  return (
    <div className="space-y-3">
      {/* What the chart says, in words, before the reader parses the shape. */}
      <p className="text-[12px] text-muted-foreground">
        {change === 0
          ? "تعداد یافته‌ها از اولین اسکن این بازه تغییری نکرده است."
          : change < 0
            ? `${faNum(Math.abs(change))} یافته نسبت به اولین اسکن این بازه کمتر شده است.`
            : `${faNum(change)} یافته نسبت به اولین اسکن این بازه بیشتر شده است.`}
      </p>

      <div className="flex items-end gap-2">
        {shown.map(p => {
          const total = totalOf(p);
          const segments = SERIES
            .map(s => ({ s, value: p[s.toLowerCase() as "critical" | "high" | "medium" | "low"] }))
            .filter(seg => seg.value > 0);

          return (
            <div key={p.takenAt} className="flex-1 min-w-0 flex flex-col items-center gap-1.5">
              {/* Capped and centred: with only a few scans, a column stretched
                  across its whole slot reads as a slab rather than a mark. The
                  leftover width is meant to be air. */}
              <div
                className="w-full max-w-[38px] h-32 flex flex-col justify-end"
                title={
                  `${faDate(p.takenAt)}\n`
                  + `${faNum(total)} یافته روی ${faNum(p.hosts)} میزبان\n`
                  + SERIES.map(s =>
                      `${SEV_FA[s]}: ${faNum(p[s.toLowerCase() as "critical" | "high" | "medium" | "low"])}`,
                    ).join(" · ")
                }
              >
                {/* Segments are separated by a 2px gap in the surface colour
                    rather than a stroke, so neighbouring severities stay
                    distinct without adding ink that is not data. */}
                <div
                  className="w-full flex flex-col justify-end gap-[2px]"
                  style={{ height: `${Math.max((total / max) * 100, total > 0 ? 3 : 0)}%` }}
                >
                  {segments.map((seg, i) => (
                    <div
                      key={seg.s}
                      className={`w-full min-h-[3px] ${i === 0 ? "rounded-t-[4px]" : ""}`}
                      style={{ flexGrow: seg.value, background: SEV_COLOR[seg.s] }}
                    />
                  ))}
                </div>
              </div>
              <span className="text-[10px] font-mono tabular-nums text-muted-foreground whitespace-nowrap">
                {shortDate(p.takenAt)}
              </span>
            </div>
          );
        })}
      </div>

      {/* Four series, so a legend is not optional. */}
      <div className="flex flex-wrap gap-x-4 gap-y-1.5 pt-1 border-t border-border">
        {SERIES.map(s => (
          <span key={s} className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
            <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ background: SEV_COLOR[s] }} />
            {SEV_FA[s]}
          </span>
        ))}
      </div>
    </div>
  );
}
