// Client for the Afrakav Go backend. All data endpoints require a Bearer
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

// exploitEase mirrors the backend's normalised reading of the Nessus
// exploitability_ease field.
export type ExploitEase = "public-exploit" | "no-exploit-needed" | "none-known" | "difficult";

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
  // Exploit intelligence from the Nessus plugin. A finding with a published
  // exploit is the one to fix first, whatever its CVSS score says.
  exploitAvailable: boolean;
  exploitedByMalware: boolean;
  exploitEase?: ExploitEase;
  exploitFrameworks?: string[];
}

export interface HostRecord {
  ip: string;
  hostnames: string[];
  domains: string[];
  org: string;
  os: string;
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
  disabled: boolean;
  totpEnabled: boolean;
}

export interface Customer extends User {
  hostCount: number;
  scanCount: number;
  lastScan: string | null;
}

export interface Scan {
  id: number;
  customerId: number;
  filename: string;
  hostsCount: number;
  uploadedAt: string;
}

export interface AuditEvent {
  id: number;
  occurredAt: string;
  actorId: number | null;
  actorUsername: string;
  actorRole: string;
  action: string;
  outcome: "success" | "failure" | "denied";
  targetType: string;
  targetId: string;
  targetLabel: string;
  customerId: number | null;
  ip: string;
  userAgent: string;
  details: Record<string, unknown>;
}

export interface Stats {
  hosts: number;
  openPorts: number;
  totalCVEs: number;
  source: string;
  bySeverity: Record<string, number>;
  exploitableFindings: number;
  exploitableHosts: number;
  malwareFindings: number;
}

const API_BASE: string =
  (import.meta as any).env?.VITE_API_URL?.replace(/\/$/, "") ?? "";

// Storage key kept from the platform's earlier name so a rename does not sign
// everyone out.
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
  "username must be at least 3 characters": "نام کاربری باید دست‌کم ۳ نویسه باشد",
  "password must be at least 12 characters": "رمز عبور باید دست‌کم ۱۲ نویسه باشد",
  "this password is too easy to guess": "این رمز عبور بیش از حد ساده است؛ رمز دیگری انتخاب کنید",
  "current password is incorrect": "رمز عبور فعلی نادرست است",
  "the verification code is not correct": "کد تأیید نادرست است",
  "this sign-in has expired; start again": "مهلت ورود به پایان رسید؛ لطفاً دوباره وارد شوید",
  "two-factor authentication is already on": "ورود دو عاملی از قبل فعال است",
  "start the two-factor setup first": "ابتدا مراحل فعال‌سازی را شروع کنید",
  "could not start two-factor setup": "شروع فعال‌سازی ورود دو عاملی با خطا مواجه شد",
  "could not finish two-factor setup": "تکمیل فعال‌سازی ورود دو عاملی با خطا مواجه شد",
  "could not turn two-factor off": "غیرفعال‌سازی ورود دو عاملی با خطا مواجه شد",
  "could not change the password": "تغییر رمز عبور با خطا مواجه شد",
  "could not update the account": "به‌روزرسانی حساب با خطا مواجه شد",
  "this account is suspended": "این حساب غیرفعال شده است؛ با مدیر سامانه تماس بگیرید",
  "could not parse the Nessus file": "پردازش فایل Nessus ممکن نبود؛ لطفاً از معتبر بودن فایل مطمئن شوید",
  "hash failed": "خطای داخلی سرور؛ لطفاً دوباره تلاش کنید",
  "this username is already taken": "این نام کاربری قبلاً استفاده شده است",
  "please give the organisation name": "نام سازمان را وارد کنید",
  "please give a contact name": "نام و نام خانوادگی رابط را وارد کنید",
  "please give a valid email address": "نشانی ایمیل معتبر وارد کنید",
  "please give a valid phone number": "شمارهٔ تماس معتبر وارد کنید",
  "the preferred username may use only letters, digits, dot, dash and underscore":
    "نام کاربری پیشنهادی فقط می‌تواند شامل حروف انگلیسی، رقم، نقطه، خط تیره و زیرخط باشد",
  "the note is too long": "توضیحات بیش از حد طولانی است",
  "too many requests from this address; please try again later":
    "درخواست‌های بیش از حد از این نشانی ثبت شده است؛ لطفاً بعداً تلاش کنید",
  "could not submit the request": "ثبت درخواست با خطا مواجه شد",
  "could not load the requests": "بارگیری درخواست‌ها با خطا مواجه شد",
  "this request has already been handled": "این درخواست قبلاً بررسی شده است",
  "could not update the request": "به‌روزرسانی درخواست با خطا مواجه شد",
  "could not create the customer": "ایجاد مشتری با خطا مواجه شد",
  "invalid request id": "شناسهٔ درخواست نامعتبر است",
  "unknown status filter": "فیلتر وضعیت نامعتبر است",
  "could not create customer": "ایجاد مشتری با خطا مواجه شد",
  "file too large or malformed form (max 64 MiB)": "فایل بیش از حد بزرگ یا نامعتبر است (حداکثر ۶۴ مگابایت)",
  "missing or invalid customerId": "مشتری انتخاب‌شده نامعتبر است",
  "customer not found": "مشتری مورد نظر یافت نشد",
  'missing multipart field "file"': "فایلی برای بارگذاری انتخاب نشده است",
  "could not save scan": "ذخیرهٔ اسکن با خطا مواجه شد",
  "authentication required": "برای دسترسی باید وارد شوید",
  "admin access required": "این بخش تنها برای مدیران در دسترس است",
  "access denied": "دسترسی به این داده مجاز نیست",
  "admin must specify customerId": "برای مشاهدهٔ داده‌ها ابتدا یک مشتری را انتخاب کنید",
  "could not sign out": "خروج از حساب با خطا مواجه شد",
  "could not load activity": "بارگیری فعالیت‌های حساب با خطا مواجه شد",
  "could not load events": "بارگیری رویدادها با خطا مواجه شد",
  "invalid scan id": "شناسهٔ اسکن نامعتبر است",
  "scan not found": "اسکن مورد نظر یافت نشد",
  "could not delete the scan": "حذف اسکن با خطا مواجه شد",
};

function translateError(msg: string): string {
  return ERROR_FA[msg] ?? msg;
}

// Scan files come from outside the platform, and a vulnerability's seeAlso is
// rendered as a link. Only plain http(s) addresses become an href — anything
// else (javascript:, data:) would run in the viewer's session when clicked.
export function safeHref(url: string | undefined): string | undefined {
  if (!url) return undefined;
  const trimmed = url.trim();
  return /^https?:\/\//i.test(trimmed) ? trimmed : undefined;
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
  // nginx rate-limits /api/login and answers with its own HTML error page.
  if (res.status === 429) {
    throw new ApiError("تلاش‌های ورود بیش از حد مجاز است؛ چند دقیقه بعد دوباره تلاش کنید", 429);
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

// A login either finishes outright or stops for a second factor, in which case
// the challenge carries the attempt to verifyLoginCode. The challenge is not a
// session token: it authenticates nothing on its own and expires in minutes.
export type LoginResult =
  | { kind: "signed-in"; user: User }
  | { kind: "needs-code"; challenge: string };

export async function login(username: string, password: string): Promise<LoginResult> {
  const data = await request<{ token?: string; user?: User; mfaRequired?: boolean; challenge?: string }>(
    "/api/login",
    { method: "POST", body: JSON.stringify({ username, password }) },
  );
  if (data.mfaRequired && data.challenge) {
    return { kind: "needs-code", challenge: data.challenge };
  }
  tokenStore.set(data.token!);
  return { kind: "signed-in", user: data.user! };
}

// Accepts an authenticator code or one of the account's recovery codes.
export async function verifyLoginCode(challenge: string, code: string): Promise<User> {
  const data = await request<{ token: string; user: User }>("/api/login/mfa", {
    method: "POST",
    body: JSON.stringify({ challenge, code }),
  });
  tokenStore.set(data.token);
  return data.user;
}

export interface Me {
  user: User;
  recoveryCodesRemaining: number;
}

export async function me(): Promise<Me> {
  return request<Me>("/api/me");
}

// ── access requests ───────────────────────────────────────────────────────

export interface AccessRequestForm {
  companyName: string;
  contactName: string;
  email: string;
  phone: string;
  wantedUsername?: string;
  note?: string;
}

export interface AccessRequest extends AccessRequestForm {
  id: number;
  wantedUsername: string;
  note: string;
  status: "pending" | "approved" | "rejected";
  sourceIp: string;
  createdAt: string;
  reviewedAt: string | null;
  reviewedBy: string;
  createdUserId: number | null;
}

// Public: submitting a request creates no account and grants nothing.
export function submitAccessRequest(form: AccessRequestForm): Promise<{ status: string }> {
  return request("/api/access-request", { method: "POST", body: JSON.stringify(form) });
}

export function listAccessRequests(status?: AccessRequest["status"]): Promise<AccessRequest[]> {
  return request<AccessRequest[]>(`/api/admin/access-requests${status ? `?status=${status}` : ""}`);
}

// Approving creates the customer. The admin picks the credentials — nothing the
// visitor typed into the public form is used as one.
export function approveAccessRequest(
  id: number, username: string, password: string, displayName: string,
): Promise<User> {
  return request<User>(`/api/admin/access-requests/${id}/approve`, {
    method: "POST",
    body: JSON.stringify({ username, password, displayName }),
  });
}

export function rejectAccessRequest(id: number): Promise<{ status: string }> {
  return request(`/api/admin/access-requests/${id}/reject`, { method: "POST" });
}

// ── two-factor authentication ─────────────────────────────────────────────

export interface TOTPSetup {
  secret: string;
  uri: string;
}

// Mints a secret and returns the otpauth URI to render as a QR code. Two-factor
// stays off until enableTwoFactor confirms a code from it.
export function startTwoFactorSetup(): Promise<TOTPSetup> {
  return request<TOTPSetup>("/api/2fa/setup", { method: "POST" });
}

// Turns two-factor on and returns the recovery codes, shown only this once.
export async function enableTwoFactor(code: string): Promise<string[]> {
  const data = await request<{ token: string; recoveryCodes: string[] }>("/api/2fa/enable", {
    method: "POST",
    body: JSON.stringify({ code }),
  });
  tokenStore.set(data.token);
  return data.recoveryCodes;
}

export async function disableTwoFactor(password: string): Promise<void> {
  const data = await request<{ token: string }>("/api/2fa/disable", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
  tokenStore.set(data.token);
}

// Ends the session server-side (the token is revoked immediately, not just
// forgotten) and then clears it locally either way, so a network failure
// never leaves the user stuck signed in on their own screen.
export async function logout(): Promise<void> {
  try {
    await request("/api/logout", { method: "POST" });
  } finally {
    tokenStore.clear();
  }
}

// Changing a password invalidates every token issued before it, including the
// one this session is holding, so the server hands back a replacement.
export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  const data = await request<{ token: string }>("/api/password", {
    method: "POST",
    body: JSON.stringify({ currentPassword, newPassword }),
  });
  tokenStore.set(data.token);
}

// ── customer-scoped data ────────────────────────────────────────────────────
export function fetchHosts(customerId?: number): Promise<HostRecord[]> {
  return request<HostRecord[]>(`/api/hosts${qs(customerId)}`);
}

export function fetchStats(customerId?: number): Promise<Stats> {
  return request<Stats>(`/api/stats${qs(customerId)}`);
}

export function fetchScans(customerId?: number): Promise<Scan[]> {
  return request<Scan[]>(`/api/scans${qs(customerId)}`);
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

// Resetting a customer's password signs them out of every open session.
export function resetCustomerPassword(customerId: number, password: string): Promise<{ status: string }> {
  return request(`/api/admin/customers/${customerId}/password`, {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

// Clears a customer's second factor when they have lost both their
// authenticator and their recovery codes. Only an admin can do this.
export function resetCustomerTwoFactor(customerId: number): Promise<{ status: string }> {
  return request(`/api/admin/customers/${customerId}/2fa/reset`, { method: "POST" });
}

// Suspending a customer takes effect immediately, not at token expiry.
export function setCustomerStatus(customerId: number, disabled: boolean): Promise<{ status: string }> {
  return request(`/api/admin/customers/${customerId}/status`, {
    method: "POST",
    body: JSON.stringify({ disabled }),
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

// Undoes an upload — a file assigned to the wrong customer, or hosts that
// should never have merged in. Only hosts still pointing at this scan as their
// most recent upload are removed.
export function deleteScan(scanId: number, customerId: number): Promise<{ status: string; hostsRemoved: number }> {
  return request(`/api/admin/scans/${scanId}/delete`, {
    method: "POST",
    body: JSON.stringify({ customerId }),
  });
}

// ── security events ──────────────────────────────────────────────────────────

export interface EventFilter {
  action?: string;
  outcome?: string;
  actor?: string;
  customerId?: number;
  cursor?: number;
}

function eventQuery(f: EventFilter): string {
  const params = new URLSearchParams();
  if (f.action) params.set("action", f.action);
  if (f.outcome) params.set("outcome", f.outcome);
  if (f.actor) params.set("actor", f.actor);
  if (f.customerId != null) params.set("customerId", String(f.customerId));
  if (f.cursor != null) params.set("cursor", String(f.cursor));
  const s = params.toString();
  return s ? `?${s}` : "";
}

// Admin: the full security log — logins, admin actions, and tenant-data views
// across every account.
export function listAuditEvents(filter: EventFilter = {}): Promise<{ events: AuditEvent[] }> {
  return request(`/api/admin/events${eventQuery(filter)}`);
}

// The signed-in account's own activity: logins, password and two-factor
// changes. Available to admins and customers alike.
export function listMyEvents(cursor?: number): Promise<{ events: AuditEvent[] }> {
  return request(`/api/events${cursor != null ? `?cursor=${cursor}` : ""}`);
}

// Action labels shown in the events table. Unknown actions (a future release
// added one this build does not know) fall back to the raw string.
export const EVENT_ACTION_FA: Record<string, string> = {
  "login.success": "ورود موفق",
  "login.failed": "ورود ناموفق",
  "login.refused_disabled": "ورود رد شد (حساب غیرفعال)",
  "login.mfa_challenge": "رمز عبور درست — در انتظار کد دوعاملی",
  "login.mfa_failed": "کد دوعاملی نادرست",
  "login.mfa_replay": "تلاش برای استفادهٔ دوبارهٔ کد دوعاملی",
  "login.recovery_code_used": "استفاده از کد بازیابی",
  "logout": "خروج",
  "password.changed": "تغییر رمز عبور",
  "password.change_refused": "تغییر رمز عبور رد شد",
  "password.reset_by_admin": "بازنشانی رمز عبور توسط مدیر",
  "2fa.setup_started": "شروع فعال‌سازی ورود دو عاملی",
  "2fa.enabled": "فعال‌سازی ورود دو عاملی",
  "2fa.disabled": "غیرفعال‌سازی ورود دو عاملی",
  "2fa.disable_refused": "غیرفعال‌سازی ورود دو عاملی رد شد",
  "2fa.reset_by_admin": "بازنشانی ورود دو عاملی توسط مدیر",
  "customer.created": "ایجاد مشتری",
  "customer.suspended": "غیرفعال‌سازی مشتری",
  "customer.restored": "فعال‌سازی مشتری",
  "request.received": "درخواست دسترسی جدید",
  "request.throttled": "درخواست دسترسی مسدود شد (محدودیت نرخ)",
  "request.approved": "تأیید درخواست دسترسی",
  "request.rejected": "رد درخواست دسترسی",
  "scan.uploaded": "بارگذاری اسکن",
  "scan.deleted": "حذف اسکن",
  "admin.tenant_viewed": "مشاهدهٔ داده‌های مشتری توسط مدیر",
  "system.started": "راه‌اندازی سامانه",
  "system.bootstrap_admin_created": "ایجاد حساب مدیر اولیه",
  "system.bootstrap_demo_seeded": "بارگذاری اسکن نمونه",
  "audit.viewed": "مشاهدهٔ رویدادها",
};

export const EVENT_OUTCOME_FA: Record<string, string> = {
  success: "موفق",
  failure: "ناموفق",
  denied: "رد شد",
};
