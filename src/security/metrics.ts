const counters = new Map<number, number>();
let totalRequests = 0;

export function observeRequest(statusCode: number): void {
  totalRequests += 1;
  counters.set(statusCode, (counters.get(statusCode) ?? 0) + 1);
}

export function renderPrometheusMetrics(): string {
  const lines = [
    "# HELP auth_http_requests_total Total HTTP requests handled by the auth service",
    "# TYPE auth_http_requests_total counter",
    `auth_http_requests_total ${totalRequests}`,
    "# HELP auth_http_responses_total HTTP responses grouped by status code",
    "# TYPE auth_http_responses_total counter",
  ];
  for (const [status, count] of [...counters.entries()].sort(
    ([a], [b]) => a - b,
  )) {
    lines.push(`auth_http_responses_total{status="${status}"} ${count}`);
  }
  lines.push(
    "# HELP auth_process_uptime_seconds Process uptime in seconds",
    "# TYPE auth_process_uptime_seconds gauge",
    `auth_process_uptime_seconds ${process.uptime()}`,
  );
  return `${lines.join("\n")}\n`;
}

