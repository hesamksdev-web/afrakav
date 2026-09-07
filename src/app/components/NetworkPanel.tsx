import { useMemo } from "react";
import { Network, Cpu } from "lucide-react";
import { HostRecord } from "../api";

const faNum = (n: number) => n.toLocaleString("fa-IR");

// A .nessus file carries no location data, so the platform describes where a
// host sits the only way the scan actually knows: its subnet and its operating
// system. Both breakdowns are computed from the customer's own hosts.
interface Group {
  key: string;
  label: string;
  hosts: number;
  atRisk: number;   // hosts carrying a critical finding or a published exploit
  query: string;    // search that narrows the view to this group
}

/** 10.20.30.11 → 10.20.30 — anything that is not a dotted quad is grouped apart. */
function subnetOf(ip: string): string | null {
  const parts = ip.split(".");
  if (parts.length !== 4 || parts.some(p => p === "" || Number.isNaN(Number(p)))) return null;
  return parts.slice(0, 3).join(".");
}

/** Collapse a long Nessus OS string to the family people actually talk about. */
function osFamily(os: string): string {
  const v = (os || "").toLowerCase();
  if (!v || v === "unknown") return "نامشخص";
  if (v.includes("windows server")) return "Windows Server";
  if (v.includes("windows")) return "Windows";
  if (v.includes("ubuntu")) return "Ubuntu";
  if (v.includes("debian")) return "Debian";
  if (v.includes("centos")) return "CentOS";
  if (v.includes("red hat") || v.includes("rhel")) return "Red Hat";
  if (v.includes("linux")) return "Linux";
  if (v.includes("vmware") || v.includes("esxi")) return "VMware ESXi";
  if (v.includes("cisco") || v.includes("ios")) return "Cisco";
  if (v.includes("mikrotik")) return "MikroTik";
  if (v.includes("freebsd")) return "FreeBSD";
  if (v.includes("mac os") || v.includes("macos")) return "macOS";
  return os.split(/[\s,(]/)[0] || "نامشخص";
}

const isAtRisk = (h: HostRecord) =>
  h.vulns.some(v => v.severity === "Critical" || v.exploitAvailable);

function group(hosts: HostRecord[], by: "subnet" | "os"): Group[] {
  const map = new Map<string, Group>();
  for (const h of hosts) {
    const key = by === "subnet" ? subnetOf(h.ip) : osFamily(h.os);
    if (!key) continue;
    const cur =
      map.get(key) ??
      {
        key,
        label: by === "subnet" ? `${key}.0/24` : key,
        hosts: 0,
        atRisk: 0,
        query: by === "subnet" ? `subnet:${key}` : `os:${key}`,
      };
    cur.hosts += 1;
    if (isAtRisk(h)) cur.atRisk += 1;
    map.set(key, cur);
  }
  return [...map.values()].sort((a, b) => b.hosts - a.hosts || a.key.localeCompare(b.key));
}

export default function NetworkPanel({ hosts, onSearch }: {
  hosts: HostRecord[];
  onSearch: (q: string) => void;
}) {
  const subnets = useMemo(() => group(hosts, "subnet"), [hosts]);
  const osFamilies = useMemo(() => group(hosts, "os"), [hosts]);

  if (hosts.length === 0) return null;

  return (
    <div className="grid sm:grid-cols-2 gap-3">
      <Column
        icon={<Network size={13} className="text-primary" />}
        title="پراکندگی شبکه"
        subtitle={`${faNum(subnets.length)} زیرشبکه`}
        groups={subnets}
        onSearch={onSearch}
      />
      <Column
        icon={<Cpu size={13} className="text-primary" />}
        title="سیستم‌عامل‌ها"
        subtitle={`${faNum(osFamilies.length)} خانواده`}
        groups={osFamilies}
        onSearch={onSearch}
      />
    </div>
  );
}

function Column({ icon, title, subtitle, groups, onSearch }: {
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  groups: Group[];
  onSearch: (q: string) => void;
}) {
  const max = Math.max(...groups.map(g => g.hosts), 1);
  const shown = groups.slice(0, 8);

  return (
    <div className="bg-card border border-border rounded overflow-hidden">
      <div className="px-4 py-2.5 border-b border-border bg-secondary/20 flex items-center gap-2">
        {icon}
        <span className="text-xs font-semibold text-foreground">{title}</span>
        <span className="ms-auto text-[10px] text-muted-foreground">{subtitle}</span>
      </div>

      <div className="p-3 space-y-2">
        {shown.map(g => (
          <button
            key={g.key}
            onClick={() => onSearch(g.query)}
            title={`نمایش میزبان‌های ${g.label}`}
            className="w-full text-start group"
          >
            <div className="flex items-baseline gap-2 mb-1">
              <span className="text-[11px] font-mono text-foreground group-hover:text-primary transition-colors truncate" dir="ltr">
                {g.label}
              </span>
              <span className="ms-auto text-[11px] font-mono text-muted-foreground tabular-nums">
                {faNum(g.hosts)}
              </span>
              {g.atRisk > 0 && (
                <span className="text-[10px] font-mono text-[#ff3b3b] tabular-nums" title="میزبان‌های دارای یافتهٔ بحرانی یا اکسپلویت">
                  ⚠ {faNum(g.atRisk)}
                </span>
              )}
            </div>
            {/* Bar length is the host count; the red head is the at-risk share. */}
            <div className="h-1.5 rounded-sm bg-secondary overflow-hidden flex" dir="ltr">
              <div className="bg-[#ff3b3b]" style={{ width: `${(g.atRisk / max) * 100}%` }} />
              <div className="bg-primary/50 group-hover:bg-primary transition-colors"
                   style={{ width: `${((g.hosts - g.atRisk) / max) * 100}%` }} />
            </div>
          </button>
        ))}

        {groups.length > shown.length && (
          <p className="text-[10px] text-muted-foreground pt-1">
            و {faNum(groups.length - shown.length)} مورد دیگر
          </p>
        )}
      </div>
    </div>
  );
}
