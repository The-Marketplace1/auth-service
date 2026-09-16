export class ServiceError extends Error {
  readonly status: number;
  readonly fields?: Record<string, string>;

  constructor(message: string, status = 500, fields?: Record<string, string>) {
    super(message);
    this.name = "ServiceError";
    this.status = status;
    this.fields = fields;
  }
}

export function serviceErrorDetails(error: unknown): {
  status: number;
  message: string;
  fields?: Record<string, string>;
} {
  if (error instanceof ServiceError) {
    return {
      status: error.status,
      message: error.status >= 500 ? "Internal server error" : error.message,
      fields: error.fields,
    };
  }

  const candidate = error as {
    status?: unknown;
    message?: unknown;
    fields?: unknown;
  };
  const status =
    typeof candidate?.status === "number" &&
    Number.isInteger(candidate.status) &&
    candidate.status >= 400 &&
    candidate.status <= 599
      ? candidate.status
      : 500;
  const candidateMessage =
    typeof candidate?.message === "string"
      ? candidate.message
      : "Internal server error";
  const message = status >= 500 ? "Internal server error" : candidateMessage;
  const fields =
    candidate?.fields &&
    typeof candidate.fields === "object" &&
    !Array.isArray(candidate.fields)
      ? (candidate.fields as Record<string, string>)
      : undefined;

  return { status, message, fields };
}

