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
