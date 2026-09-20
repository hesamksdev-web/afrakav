import { faNum } from "../format";

export interface BarDatum {
  key: string;
  label: string;
  value: number;
  /** Mark colour. Defaults to the brand accent for a single-series chart. */
  color?: string;
  /** Search this row narrows to. Without one the row is a plain readout. */
  query?: string;
  /** Latin labels (plugin names, ports, families) need their own direction. */
  ltr?: boolean;
  /** Full text for the hover tooltip; falls back to "label: value". */
  title?: string;
}

/**
 * Horizontal bars — the form for comparing magnitudes across a short list of
 * named things.
 *
 * Three rules hold across every chart built on this:
 *   · bars are measured against the largest value in the set, so the top row
 *     fills its track and the rest read as a share of it;
 *   · the label and the count are ordinary text, never the mark's colour, so
 *     a pale hue never has to be legible as type;
 *   · the count sits past the end of the bar, so a value of one still prints
 *     its number instead of being clipped by its own mark.
 */
export default function BarList({ data, labelWidth = "5rem", onSearch }: {
  data: BarDatum[];
  labelWidth?: string;
  onSearch?: (q: string) => void;
}) {
  const max = Math.max(...data.map(d => d.value), 1);

  return (
    <div className="space-y-0.5">
      {data.map(d => {
        const clickable = Boolean(d.query && onSearch && d.value > 0);
        return (
          <button
            key={d.key}
            onClick={clickable ? () => onSearch!(d.query!) : undefined}
            disabled={!clickable}
            title={d.title ?? `${d.label}: ${faNum(d.value)}`}
            style={{ gridTemplateColumns: `${labelWidth} minmax(0, 1fr) 2.75rem` }}
            className="w-full grid items-center gap-3 px-2 py-1.5 rounded transition-colors
                       enabled:hover:bg-secondary/40 disabled:cursor-default
                       disabled:opacity-55"
          >
            <span className="flex items-center gap-1.5 min-w-0">
              <span className="w-2 h-2 rounded-sm flex-shrink-0"
                    style={{ background: d.color ?? "var(--primary)" }} />
              <span
                dir={d.ltr ? "ltr" : undefined}
                style={d.ltr ? { textAlign: "start" } : undefined}
                className={`text-[12px] text-foreground truncate ${d.ltr ? "font-mono" : ""}`}
              >
                {d.label}
              </span>
            </span>

            <span className="h-3.5 rounded-sm bg-secondary/50 flex">
              <span
                className="h-full rounded-s-none rounded-e-[4px]"
                style={{ width: `${(d.value / max) * 100}%`, background: d.color ?? "var(--primary)" }}
              />
            </span>

            <span className="text-[12px] font-mono tabular-nums text-muted-foreground text-end">
              {faNum(d.value)}
            </span>
          </button>
        );
      })}
    </div>
  );
}
