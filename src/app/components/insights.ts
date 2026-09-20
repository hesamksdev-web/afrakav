import { HostRecord, Severity } from "../api";
import { SEV_COLOR, SEV_FA, SEV_ORDER, sevRank, worstSeverity } from "./severity";
import { BarDatum } from "./BarList";
import { faNum } from "../format";

// Everything here is derived from the hosts the backend already scoped to the
// signed-in account, so no dashboard panel needs its own request and none can
// reach another tenant's data.

/**
 * The same finding sitting on many hosts is one fix, not many. Grouping by
 * plugin turns a long findings list into a short work list — usually the most
 * useful thing a vulnerability dashboard can say.
 */
export function topRepeatedFindings(hosts: HostRecord[], limit = 6): BarDatum[] {
  const byPlugin = new Map<string, {
    name: string; cve: string; severity: Severity; ips: Set<string>;
  }>();

  for (const h of hosts) {
    for (const v of h.vulns) {
      const key = v.pluginId || v.name;
      const cur = byPlugin.get(key) ?? {
        name: v.name, cve: v.cve, severity: v.severity, ips: new Set<string>(),
      };
      // Keep the worst severity seen for this plugin across hosts.
      if (sevRank(v.severity) > sevRank(cur.severity)) cur.severity = v.severity;
      cur.ips.add(h.ip);
      byPlugin.set(key, cur);
    }
  }

  return [...byPlugin.entries()]
    .map(([key, f]) => ({ key, ...f, hosts: f.ips.size }))
    .sort((a, b) => b.hosts - a.hosts || sevRank(b.severity) - sevRank(a.severity))
    .slice(0, limit)
    .map(f => ({
      key: f.key,
      label: f.name,
      value: f.hosts,
      color: SEV_COLOR[f.severity],
      ltr: true,
      // A CVE is the sharper search when the finding carries one.
      query: f.cve && f.cve !== "N/A" ? `cve:${f.cve}` : f.name,
      title: `${f.name}\n${SEV_FA[f.severity]} · روی ${faNum(f.hosts)} میزبان`
        + (f.cve && f.cve !== "N/A" ? ` · ${f.cve}` : ""),
    }));
}

/**
 * How much of the estate is affected at all, counted in hosts rather than
 * findings. The severity chart answers "how bad are the findings"; this one
 * answers "how much of my network is involved", which is the question a
 * manager actually asks.
 */
export function hostsByWorstSeverity(hosts: HostRecord[]): BarDatum[] {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 } as Record<Severity, number>;
  let clean = 0;

  for (const h of hosts) {
    const worst = worstSeverity(h.vulns);
    if (worst) counts[worst] += 1;
    else clean += 1;
  }

  const rows: BarDatum[] = SEV_ORDER
    // Info can never be a host's worst finding: the parser keeps only
    // severity 1–4, so an Info row here would always read zero.
    .filter(s => s !== "Info")
    .map(s => ({
      key: s,
      label: `بدترین: ${SEV_FA[s]}`,
      value: counts[s],
      color: SEV_COLOR[s],
      query: `severity:${s.toLowerCase()}`,
      title: `${faNum(counts[s])} میزبان که بدترین یافتهٔ آن‌ها «${SEV_FA[s]}» است`,
    }));

  rows.push({
    key: "clean",
    label: "بدون یافته",
    value: clean,
    // Deliberately the brand accent, not the green already spoken for by the
    // "Low" severity step.
    color: "var(--primary)",
    title: `${faNum(clean)} میزبان بدون هیچ یافته‌ای`,
  });

  return rows;
}

/** What the attack surface is actually made of, by how many hosts expose it. */
export function topServices(hosts: HostRecord[], limit = 8): BarDatum[] {
  const byPort = new Map<number, { service: string; ips: Set<string> }>();

  for (const h of hosts) {
    for (const p of h.ports) {
      const cur = byPort.get(p.port) ?? { service: p.service, ips: new Set<string>() };
      if (!cur.service && p.service) cur.service = p.service;
      cur.ips.add(h.ip);
      byPort.set(p.port, cur);
    }
  }

  return [...byPort.entries()]
    .map(([port, v]) => ({ port, service: v.service, hosts: v.ips.size }))
    .sort((a, b) => b.hosts - a.hosts || a.port - b.port)
    .slice(0, limit)
    .map(p => ({
      key: String(p.port),
      label: p.service ? `${p.port}/${p.service}` : String(p.port),
      value: p.hosts,
      ltr: true,
      query: `port:${p.port}`,
      title: `پورت ${p.port}${p.service ? ` (${p.service})` : ""} روی ${faNum(p.hosts)} میزبان باز است`,
    }));
}

/**
 * Plugin families say what KIND of problem this is — whether the work ahead is
 * patching, configuration, or web hardening.
 */
export function topFamilies(hosts: HostRecord[], limit = 6): BarDatum[] {
  const byFamily = new Map<string, number>();

  for (const h of hosts) {
    for (const v of h.vulns) {
      const key = v.family?.trim() || "نامشخص";
      byFamily.set(key, (byFamily.get(key) ?? 0) + 1);
    }
  }

  return [...byFamily.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([family, findings]) => ({
      key: family,
      label: family,
      value: findings,
      ltr: family !== "نامشخص",
      query: family !== "نامشخص" ? `family:${family.toLowerCase()}` : undefined,
      title: `${family}: ${faNum(findings)} یافته`,
    }));
}
