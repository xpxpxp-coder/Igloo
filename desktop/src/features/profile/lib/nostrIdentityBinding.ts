import { invokeTauri } from "@/shared/api/tauri";

export type NostrIdentityBindingInput = {
  challengeId: string;
  nonce: string;
  verificationCode: string;
  origin: string;
  expiresAt: string;
};

export function signNostrIdentityBinding(
  input: NostrIdentityBindingInput,
): Promise<string> {
  return invokeTauri<string>("sign_nostr_identity_binding", input);
}

export type SnowmanWorkforceEnrollmentInput = {
  assertionId: string;
  broker: string;
  community: string;
  purpose: string;
  nonce: string;
  verificationCode: string;
  origin: string;
  expiresAt: string;
  protocol: "snowman-workforce-device-proof";
  version: "1";
};

export function signSnowmanWorkforceEnrollment(
  input: SnowmanWorkforceEnrollmentInput,
): Promise<string> {
  return invokeTauri<string>("sign_snowman_workforce_enrollment", input);
}
