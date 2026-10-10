import { MASCOT_IMAGES } from "./mascot-data";
import { ScoreColor } from "./score";

/** The project mascot, an armadillo: curled up when the code is safe, alarmed when it is not. */
export const MASCOT_NAME = "Armo";

const SAY: Record<ScoreColor, string> = {
  green: "Looks calm in here. Keep it that way.",
  yellow: "I do not like some of this. Have a look.",
  red: "Alarm! Fix the critical ones first.",
};

const ALT: Record<ScoreColor, string> = {
  green: "Armo the armadillo, curled up and calm: the project looks safe",
  yellow: "Armo the armadillo, nervous: some things need attention",
  red: "Armo the armadillo, alarmed: the project is at risk",
};

/** A `data:` URI for the image of this mood, so it can be embedded without any extra file or request. */
export function mascotDataUri(color: ScoreColor): string {
  const image = MASCOT_IMAGES[color];
  return `data:${image.mime};base64,${image.base64}`;
}

export function mascotSay(color: ScoreColor): string {
  return SAY[color];
}

export function mascotAlt(color: ScoreColor): string {
  return ALT[color];
}
