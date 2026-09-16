import { RegisterBody } from "../validation";

export function parseRegistrationInput(input: unknown) {
  const parsed = RegisterBody.safeParse(input);
  if (!parsed.success) return parsed;

  if (parsed.data.role === "professional" && !parsed.data.professionalDetails) {
    return {
      success: false as const,
      error: {
        issues: [
          {
            path: ["professionalDetails"],
            message:
              "Professional details are required for professional registration",
          },
        ],
      },
    };
  }

  if (parsed.data.role !== "professional" && parsed.data.professionalDetails) {
    return {
      success: false as const,
      error: {
        issues: [
          {
            path: ["professionalDetails"],
            message:
              "Professional details are only valid for professional registration",
          },
        ],
      },
    };
  }

  return parsed;
}

