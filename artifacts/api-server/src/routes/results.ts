import { Router, type IRouter } from "express";
import pg from "pg";

const router: IRouter = Router();
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

router.post("/scans", async (req, res) => {
  try {
    const {
      uid,
      id,
      kind,
      hostname,
      riskLevel,
      riskScore,
      indicators,
      recommendations,
      evaluatedAt,
    } = req.body ?? {};
    if (typeof uid !== "string" || typeof id !== "string" || !uid || !id) {
      res.status(400).json({ error: "uid and id required" });
      return;
    }
    await pool.query(
      `INSERT INTO scans (id, uid, kind, hostname, risk_level, risk_score, indicators, recommendations, evaluated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (uid, id) DO UPDATE SET
         risk_level = EXCLUDED.risk_level,
         risk_score = EXCLUDED.risk_score,
         indicators = EXCLUDED.indicators,
         recommendations = EXCLUDED.recommendations`,
      [
        id,
        uid,
        kind === "url" ? "url" : "message",
        hostname ?? null,
        String(riskLevel ?? "low"),
        Number(riskScore) || 0,
        JSON.stringify(indicators ?? []),
        JSON.stringify(recommendations ?? []),
        evaluatedAt ?? new Date().toISOString(),
      ],
    );
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Could not back up scan" });
  }
});

export default router;
