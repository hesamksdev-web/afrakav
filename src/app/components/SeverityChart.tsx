import { Severity } from "../api";
import { faNum } from "../format";
import BarList, { BarDatum } from "./BarList";
import { SEV_COLOR, SEV_FA, SEV_ORDER, severityQuery } from "./severity";

/**
 * Severity distribution — where the risk sits, counted in findings.
 *
 * Bars stay in severity order rather than sorting by size, because severity is
 * an ordered scale: a reader looks for "بحرانی" in the same place every time.
 * The orange and yellow steps are hard to separate by hue alone, so every row
 * carries its own label and count as text and the colour only narrows the
 * search.
 */
export default function SeverityChart({ counts, total, onSearch }: {
  counts: Record<Severity, number>;
  total: number;
  onSearch: (q: string) => void;
}) {
  const data: BarDatum[] = SEV_ORDER
    // The parser keeps only severity 1–4, so an "اطلاعاتی" row would sit at
    // zero forever. Drop it unless something ever lands there.
    .filter(s => s !== "Info" || counts[s] > 0)
    .map(s => ({
      key: s,
      label: SEV_FA[s],
      value: counts[s],
      color: SEV_COLOR[s],
      query: severityQuery(s),
      title: counts[s] === 0
        ? `${SEV_FA[s]}: بدون یافته`
        : `${SEV_FA[s]}: ${faNum(counts[s])} یافته`
          + (total > 0 ? ` (${faNum(Math.round((counts[s] / total) * 100))}٪ از کل)` : "")
          + " — نمایش میزبان‌های دارای این شدت",
    }));

  return <BarList data={data} labelWidth="4.25rem" onSearch={onSearch} />;
}
