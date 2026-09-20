import { Severity } from "../api";
import { faNum } from "../format";
import { SEV_COLOR, SEV_FA, SEV_ORDER } from "./severity";

/**
 * Severity distribution as a bar chart — the answer to "where does my risk
 * actually sit?" at a glance.
 *
 * Bars stay in severity order rather than sorting by size, because severity is
 * an ordered scale: a reader looks for "بحرانی" in the same place every time.
 * Each bar is measured against the largest severity, so the tallest bar fills
 * its track and the rest read as a share of it.
 *
 * Every row carries its own label and count in ordinary text. That is
 * deliberate: the orange and yellow steps are hard to separate by hue alone,
 * so identity never rests on the colour. The count sits past the end of the
 * bar rather than inside it, so a severity with a single finding still shows
 * its number instead of clipping it.
 */
export default function SeverityChart({ counts, total, onSelect }: {
  counts: Record<Severity, number>;
  total: number;
  onSelect: (s: Severity) => void;
}) {
  const max = Math.max(...SEV_ORDER.map(s => counts[s]), 1);

  return (
    <div className="space-y-0.5">
      {SEV_ORDER.map(s => {
        const count = counts[s];
        const share = total > 0 ? Math.round((count / total) * 100) : 0;

        return (
          <button
            key={s}
            onClick={() => onSelect(s)}
            disabled={count === 0}
            title={
              count === 0
                ? `${SEV_FA[s]}: بدون یافته`
                : `${SEV_FA[s]}: ${faNum(count)} یافته (${faNum(share)}٪ از کل) — نمایش میزبان‌های دارای این شدت`
            }
            className="w-full grid grid-cols-[4.25rem_1fr_2.75rem] items-center gap-3 px-2 py-1.5 rounded
                       transition-colors enabled:hover:bg-secondary/40 disabled:cursor-default disabled:opacity-55"
          >
            {/* The swatch carries identity; the label stays in text colour so it
                is legible whatever the severity's hue does on this surface. */}
            <span className="flex items-center gap-1.5 text-[12px] text-foreground text-start">
              <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ background: SEV_COLOR[s] }} />
              {SEV_FA[s]}
            </span>

            {/* Track is the largest severity. The bar is anchored at the label
                side and grows away from it, with a rounded data end. */}
            <span className="h-3.5 rounded-sm bg-secondary/50 flex">
              <span
                className="h-full rounded-s-none rounded-e-[4px]"
                style={{ width: `${(count / max) * 100}%`, background: SEV_COLOR[s] }}
              />
            </span>

            <span className="text-[12px] font-mono tabular-nums text-muted-foreground text-end">
              {faNum(count)}
            </span>
          </button>
        );
      })}
    </div>
  );
}
