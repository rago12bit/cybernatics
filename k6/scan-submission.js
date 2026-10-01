// 50 concurrent scans (plan §23, Week 50): measures the real POST /scans submission endpoint's own
// latency and throughput under concurrent load, against a real running Bulwark API -- not a mock
// server. Deliberately does NOT wait for a submitted scan to finish: `POST /scans` returns 202 the
// instant the job is enqueued (api/main.py's create_scan), and that enqueue latency -- not a real
// scan's multi-minute clone-and-scan time, which is an orchestration cost unrelated to the API's own
// responsiveness -- is what "50 concurrent scans" means for an API load test. The target repo
// (octocat/Hello-World) is real and tiny on purpose: every submission here really does get cloned and
// scanned by the real worker afterward, and keeping it small keeps that real downstream load light
// rather than a resource risk to the machine running this test.
import http from "k6/http";
import { check } from "k6";

const BASE_URL = __ENV.BULWARK_API_URL || "http://127.0.0.1:8000";
const TOKEN = __ENV.BULWARK_API_TOKEN;

export const options = {
  scenarios: {
    concurrent_scan_submissions: {
      executor: "constant-vus",
      vus: 50,
      duration: "20s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
  },
  summaryTrendStats: ["avg", "min", "med", "p(50)", "p(90)", "p(95)", "p(99)", "max"],
};

export default function () {
  const res = http.post(
    `${BASE_URL}/scans`,
    JSON.stringify({ source: { type: "git", url: "https://github.com/octocat/Hello-World" } }),
    {
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${TOKEN}`,
      },
    }
  );
  check(res, {
    "status is 202": (r) => r.status === 202,
    "body has a scan id": (r) => {
      try {
        return typeof JSON.parse(r.body).id === "string";
      } catch {
        return false;
      }
    },
  });
}
