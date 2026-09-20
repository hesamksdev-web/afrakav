import { Severity } from "../api";

// Severity is an ordered status scale, not a set of interchangeable categories,
// so the order is fixed everywhere it is rendered: worst first.
export const SEV_ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

export const SEV_FA: Record<Severity, string> = {
  Critical: "بحرانی",
  High: "بالا",
  Medium: "متوسط",
  Low: "پایین",
  Info: "اطلاعاتی",
};

// The product's status palette, kept as it already reads across the panel.
// Checked with a colour-vision validator: "بالا" (#ff8c00) and "متوسط"
// (#f5c518) sit close enough that a reader can struggle to separate them by
// hue alone, with or without a colour-vision deficiency, and the lighter steps
// fall under 3:1 against a white card. That is why every chart built on these
// values carries a text label and the count beside each mark — colour narrows
// the search, the label carries the meaning.
export const SEV_COLOR: Record<Severity, string> = {
  Critical: "#ff3b3b",
  High: "#ff8c00",
  Medium: "#f5c518",
  Low: "#2ea043",
  Info: "#6b7280",
};

/** The search that narrows the view to one severity. */
export const severityQuery = (s: Severity) => `severity:${s.toLowerCase()}`;

/** Worst first, so findings and hosts can be ranked consistently. */
export const sevRank = (s: Severity) => SEV_ORDER.length - SEV_ORDER.indexOf(s);

/**
 * The highest severity present on a host, or null when it carries nothing.
 * The Nessus parser only keeps findings of severity 1–4, so a host with an
 * empty list really is a host with no findings, not one with unshown ones.
 */
export function worstSeverity(vulns: { severity: Severity }[]): Severity | null {
  let worst: Severity | null = null;
  for (const v of vulns) {
    if (!worst || sevRank(v.severity) > sevRank(worst)) worst = v.severity;
  }
  return worst;
}
