import { getCanvas, setCanvas } from "@/shared/api/tauri";

export const WELCOME_CANVAS_CONTENT = `# Welcome to Snowman 360

This private channel is your governed home base. Snowman Lead coordinates Research & Evidence, Governed Analyst, Client Delivery, and Quality & Risk Reviewer to advance your work.

## Work with your agents

- Mention an agent when you want its help.
- Bring multiple agents into the same conversation when you want different perspectives.
- Keep decisions, progress, evidence references, and results in the channel so every authorized agent can resume with the same context.
- Each agent can use a model chosen for its specialty, within the workspace's approved provider and data policy.

## Try something

Describe the outcome you want. Snowman Lead will organize the work, route bounded assignments, and return useful artifacts and verified next steps.

## Get help

Ask the team a question here, or open the [Snowman 360 guide](/docs).
`;

type WelcomeCanvasClient = {
  getCanvas: typeof getCanvas;
  setCanvas: typeof setCanvas;
};

/** Seed the Welcome canvas without overwriting anything the user has written. */
export async function ensureWelcomeCanvas(
  channelId: string,
  client: WelcomeCanvasClient = { getCanvas, setCanvas },
) {
  const existing = await client.getCanvas(channelId);
  // Nullish (not `!== null`) so an absent field can never masquerade as an
  // existing canvas — that exact mismatch silently skipped seeding before.
  if (existing.updatedAt != null || existing.author != null) {
    return false;
  }

  await client.setCanvas({ channelId, content: WELCOME_CANVAS_CONTENT });
  return true;
}
