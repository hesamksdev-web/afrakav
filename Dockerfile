# ── build stage ──────────────────────────────────────────────────────────────
# Debian/glibc (not alpine/musl): the workspace pins supportedArchitectures to
# glibc, so native deps (@tailwindcss/oxide, lightningcss, rollup) resolve here.
FROM node:22-slim AS webbuild
WORKDIR /app
RUN corepack enable

# Same origin as nginx: api.ts uses relative /api/* URLs when VITE_API_URL="".
ENV VITE_API_URL=""

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
# Install exactly what the lockfile pins, and allow native postinstalls
# (@tailwindcss/oxide, lightningcss) to run.
RUN pnpm config set dangerouslyAllowAllBuilds true && pnpm install --frozen-lockfile

COPY . .
RUN pnpm build

# ── runtime stage (nginx serves static bundle + proxies /api) ─────────────────
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=webbuild /app/dist /usr/share/nginx/html
EXPOSE 80
