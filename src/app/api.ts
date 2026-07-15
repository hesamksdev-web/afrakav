// Client for the Afrashodan Go backend. All data endpoints require a Bearer
// token obtained from login(); the token is persisted in localStorage so a
// refresh keeps the session. Customer requests are scoped server-side to the
// caller — the API never returns another tenant's hosts.

export interface PortEntry {
  port: number;
  proto: "tcp" | "udp";
  service: string;
  product: string;
  banner: string;
}

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface Vuln {
  cve: string;
  pluginId: string;
  name: string;
  severity: Severity;
  cvss: number;
  family: string;
  description: string;
  solution: string;
  seeAlso?: string;
}

export interface HostRecord {
  ip: string;
  hostnames: string[];
  domains: string[];
  org: string;
  isp: string;
  asn: string;
  os: string;
  country: string;
  countryCode: string;
  city: string;
  region: string;
  lastScan: string;
  tags: string[];
  ports: PortEntry[];
  vulns: Vuln[];
}

export interface User {
  id: number;
  username: string;
  role: "admin" | "customer";
  displayName: string;
}

export interface Customer extends User {
  hostCount: number;
  scanCount: number;
  lastScan: string | null;
}

export interface Stats {
  hosts: number;
  openPorts: number;
  totalCVEs: number;
  source: string;
  bySeverity: Record<string, number>;
}

const API_BASE: string =
  (import.meta as any).env?.VITE_API_URL?.replace(/\/$/, "") ?? "";

const TOKEN_KEY = "afrashodan_token";

export const tokenStore = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
};

// The Go backend replies with English error strings; translate the known ones
// so users only ever see Persian. Unknown messages fall through unchanged.
const ERROR_FA: Record<string, string> = {
  "invalid request body": "درخواست نامعتبر است",
  "invalid username or password": "نام کاربری یا رمز عبور نادرست است",
  "could not issue token": "خطا در ایجاد نشست؛ لطفاً دوباره تلاش کنید",
  "could not load hosts": "خطا در بارگیری میزبان‌ها",
  "host not found": "میزبان مورد نظر یافت نشد",
  "lookup failed": "جست‌وجو با خطا مواجه شد",
  "could not load scans": "خطا در بارگیری اسکن‌ها",
  "could not list customers": "خطا در بارگیری فهرست مشتریان",
  "username must be at least 3 and password at least 6 characters":
    "نام کاربری باید دست‌کم ۳ و رمز عبور دست‌کم ۶ نویسه باشد",
  "hash failed": "خطای داخلی سرور؛ لطفاً دوباره تلاش کنید",
  "this username is already taken": "این نام کاربری قبلاً استفاده شده است",
  "could not create customer": "ایجاد مشتری با خطا مواجه شد",
  "file too large or malformed form (max 64 MiB)": "فایل بیش از حد بزرگ یا نامعتبر است (حداکثر ۶۴ مگابایت)",
  "missing or invalid customerId": "مشتری انتخاب‌شده نامعتبر است",
  "customer not found": "مشتری مورد نظر یافت نشد",
  'missing multipart field "file"': "فایلی برای بارگذاری انتخاب نشده است",
  "could not save scan": "ذخیرهٔ اسکن با خطا مواجه شد",
  "authentication required": "برای دسترسی باید وارد شوید",
  "admin access required": "این بخش تنها برای مدیران در دسترس است",
};

function translateError(msg: string): string {
  if (ERROR_FA[msg]) return ERROR_FA[msg];
  if (msg.startsWith("could not parse Nessus file:")) {
    return "پردازش فایل Nessus ممکن نبود؛ لطفاً از معتبر بودن فایل مطمئن شوید";
  }
  return msg;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = tokenStore.get();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (res.status === 401) {
    tokenStore.clear();
    throw new ApiError("نشست شما منقضی شده است؛ لطفاً دوباره وارد شوید", 401);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const raw = (data as any).error as string | undefined;
    throw new ApiError(raw ? translateError(raw) : `خطا در ارتباط با سرور (${res.status})`, res.status);
  }
  return data as T;
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

// ── auth ──────────────────────────────────────────────────────────────────
export async function login(username: string, password: string): Promise<User> {
  const data = await request<{ token: string; user: User }>("/api/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  tokenStore.set(data.token);
  return data.user;
}

export async function me(): Promise<User> {
  const data = await request<{ user: User }>("/api/me");
  return data.user;
}

export function logout() {
  tokenStore.clear();
}

// ── customer-scoped data ────────────────────────────────────────────────────
export function fetchHosts(customerId?: number): Promise<HostRecord[]> {
  return request<HostRecord[]>(`/api/hosts${qs(customerId)}`);
}

export function fetchStats(customerId?: number): Promise<Stats> {
  return request<Stats>(`/api/stats${qs(customerId)}`);
}

// ── admin ───────────────────────────────────────────────────────────────────
export function listCustomers(): Promise<Customer[]> {
  return request<Customer[]>("/api/admin/customers");
}

export function createCustomer(username: string, password: string, displayName: string): Promise<User> {
  return request<User>("/api/admin/customers", {
    method: "POST",
    body: JSON.stringify({ username, password, displayName }),
  });
}

export interface UploadResult {
  scan: { id: number; filename: string; hostsCount: number; uploadedAt: string };
  hostsParsed: number;
}

export function adminUpload(file: File, customerId: number): Promise<UploadResult> {
  const form = new FormData();
  form.append("file", file);
  form.append("customerId", String(customerId));
  return request<UploadResult>("/api/admin/upload", { method: "POST", body: form });
}

function qs(customerId?: number): string {
  return customerId != null ? `?customerId=${customerId}` : "";
}
