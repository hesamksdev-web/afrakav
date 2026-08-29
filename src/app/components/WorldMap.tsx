import { useMemo, useState } from "react";
import { ComposableMap, Geographies, Geography, Graticule, Marker, Sphere } from "react-simple-maps";
import { Globe } from "lucide-react";
// Land silhouette bundled at build time — no external tile/CDN requests.
import land110m from "world-atlas/land-110m.json";

const faNum = (n: number) => n.toLocaleString("fa-IR");

// ISO 3166-1 alpha-2 → [longitude, latitude] country centroids for the
// countries most likely to appear in scan data. Unknown codes are skipped.
const CENTROIDS: Record<string, [number, number]> = {
  IR: [53.7, 32.4], TR: [35.2, 39.0], IQ: [43.7, 33.2], AE: [54.0, 23.4],
  SA: [45.1, 23.9], QA: [51.2, 25.3], KW: [47.5, 29.3], OM: [56.1, 21.5],
  BH: [50.6, 26.0], AM: [45.0, 40.3], AZ: [47.6, 40.1], GE: [43.4, 42.3],
  TM: [59.6, 39.1], AF: [66.0, 33.8], PK: [69.4, 30.4], IN: [78.7, 22.9],
  RU: [96.7, 61.5], KZ: [66.9, 48.0], CN: [104.2, 35.9], JP: [138.3, 36.2],
  KR: [127.8, 36.4], SG: [103.8, 1.35], MY: [101.9, 4.2], TH: [100.9, 15.9],
  ID: [113.9, -0.8], VN: [108.3, 14.1], PH: [121.8, 12.9], HK: [114.1, 22.4],
  TW: [121.0, 23.7], IL: [34.9, 31.0], JO: [36.8, 31.3], LB: [35.9, 33.9],
  SY: [38.5, 35.0], EG: [30.8, 26.8], MA: [-7.1, 31.8], TN: [9.5, 34.0],
  DZ: [2.6, 28.2], LY: [17.2, 26.3], ZA: [24.7, -28.5], NG: [8.1, 9.6],
  KE: [37.9, 0.2], ET: [39.6, 8.6], DE: [10.4, 51.1], FR: [2.2, 46.2],
  GB: [-1.5, 52.4], NL: [5.3, 52.1], BE: [4.5, 50.6], LU: [6.1, 49.8],
  CH: [8.2, 46.8], AT: [14.6, 47.6], IT: [12.6, 42.8], ES: [-3.7, 40.2],
  PT: [-8.2, 39.7], IE: [-8.2, 53.2], SE: [16.7, 62.8], NO: [8.8, 61.2],
  FI: [26.3, 64.5], DK: [9.5, 56.1], PL: [19.4, 52.1], CZ: [15.3, 49.8],
  SK: [19.5, 48.7], HU: [19.4, 47.2], RO: [24.9, 45.9], BG: [25.5, 42.8],
  GR: [22.9, 39.0], RS: [20.8, 44.2], HR: [15.9, 45.5], UA: [31.4, 48.9],
  BY: [28.0, 53.5], LT: [23.9, 55.2], LV: [24.9, 56.9], EE: [25.5, 58.7],
  CY: [33.2, 35.0], MT: [14.4, 35.9], US: [-98.6, 39.8], CA: [-106.3, 56.1],
  MX: [-102.5, 23.9], BR: [-53.1, -10.8], AR: [-64.7, -35.4], CL: [-71.4, -35.7],
  CO: [-73.1, 3.9], PE: [-75.0, -9.2], VE: [-66.2, 7.1], AU: [134.5, -25.7],
  NZ: [172.8, -41.8],
};

export interface CountryStat {
  code: string;      // ISO2, uppercase
  name: string;      // country display name from scan data
  hosts: number;
  critical: number;
}

// Placeholder distribution shown until real geo data exists (Nessus files
// carry no location info — the backend fills country fields with "—").
// Rendered with a "sample data" badge and non-clickable markers.
export const MOCK_COUNTRY_STATS: CountryStat[] = [
  { code: "IR", name: "ایران",    hosts: 148, critical: 12 },
  { code: "AE", name: "امارات",   hosts: 34,  critical: 0 },
  { code: "TR", name: "ترکیه",    hosts: 27,  critical: 3 },
  { code: "DE", name: "آلمان",    hosts: 22,  critical: 0 },
  { code: "NL", name: "هلند",     hosts: 16,  critical: 1 },
  { code: "US", name: "آمریکا",   hosts: 14,  critical: 0 },
  { code: "GB", name: "انگلستان", hosts: 9,   critical: 0 },
  { code: "FR", name: "فرانسه",   hosts: 8,   critical: 2 },
  { code: "SG", name: "سنگاپور",  hosts: 7,   critical: 0 },
  { code: "IN", name: "هند",      hosts: 6,   critical: 0 },
  { code: "RU", name: "روسیه",    hosts: 5,   critical: 1 },
  { code: "CN", name: "چین",      hosts: 4,   critical: 0 },
  { code: "BR", name: "برزیل",    hosts: 3,   critical: 0 },
  { code: "AU", name: "استرالیا", hosts: 2,   critical: 0 },
];

export default function WorldMap({ stats, onSelect }: {
  stats: CountryStat[];
  onSelect: (countryCode: string) => void;
}) {
  const [hovered, setHovered] = useState<CountryStat | null>(null);

  // Only stats whose country code maps to a known centroid can be drawn.
  // Placeholder codes like "—" don't qualify, so an all-placeholder dataset
  // falls back to the badged sample distribution.
  const { placed, sample } = useMemo(() => {
    const real = stats
      .filter(s => CENTROIDS[s.code])
      .sort((a, b) => b.hosts - a.hosts);
    if (real.length > 0) return { placed: real, sample: false };
    return { placed: MOCK_COUNTRY_STATS, sample: true };
  }, [stats]);
  const maxHosts = Math.max(1, ...placed.map(s => s.hosts));

  return (
    <div className="border border-border rounded bg-card overflow-hidden mb-6">
      <div className="px-4 py-3 border-b border-border bg-secondary/20 flex items-center gap-2">
        <Globe size={13} className="text-primary" />
        <span className="text-xs font-semibold text-foreground">پراکندگی جغرافیایی میزبان‌ها</span>
        {sample && (
          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded border border-[#f5c518]/40 bg-[#f5c518]/10 text-[#b58900] dark:text-[#f5c518]">
            دادهٔ نمونه
          </span>
        )}
        <span className="ms-auto text-[10px] text-muted-foreground">
          {hovered
            ? <>«{hovered.name}» — {faNum(hovered.hosts)} میزبان{hovered.critical > 0 && <span className="text-destructive"> · {faNum(hovered.critical)} بحرانی</span>}</>
            : sample
              ? "نمایش آزمایشی — با افزودن موقعیت واقعی میزبان‌ها فعال می‌شود"
              : "برای فیلتر کردن نتایج، روی یک کشور کلیک کنید"}
        </span>
      </div>

      <div dir="ltr" className="relative">
        <ComposableMap
          projection="geoNaturalEarth1"
          projectionConfig={{ scale: 160, center: [15, 5] }}
          width={900}
          height={420}
          style={{ width: "100%", height: "auto", display: "block" }}
        >
          <defs>
            <radialGradient id="wm-ocean" cx="50%" cy="42%" r="75%">
              <stop offset="0%" stopColor="var(--map-ocean-1)" />
              <stop offset="100%" stopColor="var(--map-ocean-2)" />
            </radialGradient>
            <filter id="wm-glow" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur stdDeviation="3.2" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          <Sphere id="wm-sphere" fill="url(#wm-ocean)" stroke="none" strokeWidth={0} />
          <Graticule stroke="var(--map-grid)" strokeWidth={0.4} step={[20, 20]} />

          <Geographies geography={land110m as any}>
            {({ geographies }) => geographies.map(geo => (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill="var(--map-land)"
                stroke="var(--map-stroke)"
                strokeWidth={0.5}
                style={{ default: { outline: "none" }, hover: { outline: "none" }, pressed: { outline: "none" } }}
              />
            ))}
          </Geographies>

          {placed.map(s => {
            const r = 4 + 9 * Math.sqrt(s.hosts / maxHosts);
            const hot = s.critical > 0;
            const color = hot ? "var(--destructive)" : "var(--primary)";
            const isHovered = hovered?.code === s.code;
            return (
              <Marker
                key={s.code}
                coordinates={CENTROIDS[s.code]}
                onClick={() => { if (!sample) onSelect(s.code); }}
                onMouseEnter={() => setHovered(s)}
                onMouseLeave={() => setHovered(null)}
                style={{ default: { cursor: sample ? "default" : "pointer" } }}
              >
                {/* Radar sweep */}
                <circle r={r + 4} fill="none" stroke={color} strokeWidth={0.8} opacity={0.4}>
                  <animate attributeName="r" values={`${r};${r + 14}`} dur="2.8s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.45;0" dur="2.8s" repeatCount="indefinite" />
                </circle>
                <circle r={r + 4} fill={color} opacity={0.1}>
                  <animate attributeName="r" values={`${r + 2};${r + 8};${r + 2}`} dur="2.8s" repeatCount="indefinite" />
                </circle>
                {/* Body + glowing core */}
                <circle r={r} fill={color} opacity={isHovered ? 0.4 : 0.24} stroke={color} strokeOpacity={0.8} strokeWidth={1} />
                <circle r={2} fill={color} filter="url(#wm-glow)" />
                <text
                  textAnchor="middle"
                  y={-r - 6}
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: isHovered ? 10 : 9,
                    fontWeight: isHovered ? 700 : 400,
                    fill: isHovered ? color : "var(--map-label)",
                    pointerEvents: "none",
                    transition: "font-size .15s",
                  }}
                >
                  {s.code} · {s.hosts}
                </text>
              </Marker>
            );
          })}
        </ComposableMap>

        {/* Legend */}
        <div className="absolute bottom-2.5 left-3 flex items-center gap-3 text-[9px] font-mono px-2 py-1 rounded border border-border/60 bg-card/70 backdrop-blur-sm" style={{ color: "var(--map-label)" }}>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-primary/80" /> hosts
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-destructive/80" /> critical
          </span>
        </div>
      </div>

      {/* Country strip */}
      {placed.length > 0 && (
        <div className="px-4 py-2.5 border-t border-border flex flex-wrap gap-1.5">
          {placed.map(s => (
            <button
              key={s.code}
              onClick={() => { if (!sample) onSelect(s.code); }}
              onMouseEnter={() => setHovered(s)}
              onMouseLeave={() => setHovered(null)}
              className={`text-[10px] rounded border px-2 py-0.5 transition-colors ${sample ? "cursor-default" : "cursor-pointer"}
                ${s.critical > 0
                  ? "border-destructive/25 text-destructive/80 hover:bg-destructive/10"
                  : "border-border text-muted-foreground hover:text-primary hover:border-primary/30"}`}
            >
              {s.name} · {faNum(s.hosts)}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
