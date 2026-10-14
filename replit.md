# CyberShield AI

A beginner-friendly cybersecurity web app that explains potential risks in suspicious URLs and messages and teaches practical online safety.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm --filter @workspace/cybershield-ai run dev` — run the web app
- `pnpm --filter @workspace/cybershield-ai run typecheck` — typecheck the web app
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Firebase browser configuration is optional for local-only use. See `artifacts/cybershield-ai/FIREBASE_SETUP.md` to enable email/password auth and Firestore.

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)
- Web app: React + Vite

## Where things live

- `artifacts/cybershield-ai` — CyberShield AI web app, learning center, and Firebase setup
- `artifacts/api-server/src/routes/analysis.ts` — safe rule-based URL and message assessment
- `lib/api-spec/openapi.yaml` — analysis API contract and generated client/schema source
- `artifacts/cybershield-ai/firestore.rules` — owner-only access rules for cloud history and learning progress

## Architecture decisions

- Submitted URLs are parsed locally by the analysis server and are never fetched or opened.
- The analyzer is transparent rule-based assessment, not a trained model or live threat-intelligence lookup.
- Scan history must not retain submitted message text or a full URL; retain only minimal metadata and, for URLs, a hostname.
- Firebase authentication and cloud history are enabled only when the app has a Firebase web configuration and the matching Firestore rules are applied.

## Product

CyberShield AI helps students, farmers, and people with limited technical knowledge assess suspicious links and messages, understand the risk signals in simple language, review their scan history, and learn safer online habits. It supports English, Hindi, and Telugu.

## User preferences

Keep cybersecurity explanations accessible and careful: a risk score is an assessment, not a guarantee or a definitive fraud verdict.

## Gotchas

_Populate as you build — sharp edges, "always run X before Y" rules._

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
