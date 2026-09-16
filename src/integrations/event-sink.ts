export interface AuthEventSinkPayload {
  type: string;
  occurredAt: string;
  data: {
    userId: string | null;
    sessionId: string | null;
    metadata: Record<string, unknown>;
    delivery: Record<string, unknown> | null;
  };
}

export async function publishAuthEvent(
  url: string,
  payload: AuthEventSinkPayload,
): Promise<void> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(5_000),
  });

  if (!response.ok) {
    throw new Error(`Auth event sink returned HTTP ${response.status}`);
  }
}

