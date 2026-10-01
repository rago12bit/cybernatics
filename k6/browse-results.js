// 500 concurrent users browsing results (plan §23, Week 50): read-heavy traffic against the real
// Bulwark API -- listing scans, opening a scan's detail, and paging its findings -- the same
// endpoints the web app's own scan list and report screens call. BULWARK_SCAN_ID should be a real,
// already-completed scan's id (`curl -H "Authorization: Bearer $TOKEN" $BASE_URL/scans | jq -r
// '.[0].id'` picks one); every request in this script is real, against real Postgres-backed data,
// not a fixture.
import http from "k6/http";
import { check } from "k6";

const BASE_URL = __ENV.BULWARK_API_URL || "http://127.0.0.1:8000";
const TOKEN = __ENV.BULWARK_API_TOKEN;
const SCAN_ID = __ENV.BULWARK_SCAN_ID;

export const options = {
  scenarios: {
    concurrent_browsing: {
      // Ramping, not an instant 500-VU burst: a real user base doesn't open 500 simultaneous
      // requests at t=0 (a `constant-vus` run tried first did exactly that and mostly measured
      // thundering-herd pool contention, not steady-state browsing latency -- see
      // docs/v2-week50-verification.md for both numbers). Ramping to 500 and holding there is what
      // "500 concurrent users browsing results" actually means as a sustained load.
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "15s", target: 500 },
        { duration: "30s", target: 500 },
        { duration: "5s", target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
  },
  summaryTrendStats: ["avg", "min", "med", "p(50)", "p(90)", "p(95)", "p(99)", "max"],
};

const authHeaders = { headers: { Authorization: `Bearer ${TOKEN}` } };

export default function () {
  const list = http.get(`${BASE_URL}/scans`, authHeaders);
  check(list, { "list: status is 200": (r) => r.status === 200 });

  if (SCAN_ID) {
    const detail = http.get(`${BASE_URL}/scans/${SCAN_ID}`, authHeaders);
    check(detail, { "detail: status is 200": (r) => r.status === 200 });

    const findings = http.get(`${BASE_URL}/scans/${SCAN_ID}/findings`, authHeaders);
    check(findings, { "findings: status is 200": (r) => r.status === 200 });
  }
}
