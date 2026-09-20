// Shared display formatting. Persian digits and the Persian calendar are the
// interface's defaults, so every number and date the customer reads goes
// through here rather than being formatted at each call site.

export const faNum = (n: number) => n.toLocaleString("fa-IR");

/**
 * Relative time against the real clock. A scan timestamp that sits slightly in
 * the future (clock skew between the scanner and the browser) reads as
 * "هم‌اکنون" rather than a negative age.
 */
export function timeAgo(iso: string): string {
  const then = new Date(iso).getTime();
  if (!Number.isFinite(then)) return "نامشخص";

  const minutes = Math.round((Date.now() - then) / 60000);
  if (minutes < 1) return "هم‌اکنون";
  if (minutes < 60) return `${faNum(minutes)} دقیقه پیش`;

  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${faNum(hours)} ساعت پیش`;

  const days = Math.round(hours / 24);
  if (days < 31) return `${faNum(days)} روز پیش`;

  const months = Math.round(days / 30);
  if (months < 12) return `${faNum(months)} ماه پیش`;

  return `${faNum(Math.round(months / 12))} سال پیش`;
}

/** A full date in the Persian calendar, e.g. ۲۹ شهریور ۱۴۰۵. */
export function faDate(iso: string): string {
  const d = new Date(iso);
  if (!Number.isFinite(d.getTime())) return "نامشخص";
  return d.toLocaleDateString("fa-IR", { year: "numeric", month: "long", day: "numeric" });
}
