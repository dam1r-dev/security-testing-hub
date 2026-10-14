/**
 * A time budget for the analysis of ONE file.
 *
 * A scan reads code written by someone else, and that someone can write a file that makes an analyzer slow (a quadratic
 * walk over 300 000 functions, a 20 000-step assignment chain) or run out of stack (a 200 000-term `1+1+1+...`). One file
 * must never hold a whole scan, or a CI job, hostage: the walks that every analyzer is built on check the budget, and
 * when it is used up they stop with `BudgetExceeded`, which `scanSource` turns into a note on that file ("analysis
 * stopped, results for it may be incomplete") while the rest of the project is scanned normally.
 */

export class BudgetExceeded extends Error {
  constructor() {
    super("the analysis of this file took too long");
    this.name = "BudgetExceeded";
  }
}

/** Milliseconds of analysis one file may use (parsing has its own limit, see parsers/ast-parser.ts). */
export const FILE_BUDGET_MS = 15_000;

let deadline = Number.POSITIVE_INFINITY;
let ticks = 0;

/** Starts a budget; returns the function that ends it (restoring whatever budget was active before). */
export function startBudget(ms: number = FILE_BUDGET_MS): () => void {
  const previous = deadline;
  deadline = Math.min(previous, Date.now() + ms);
  return () => {
    deadline = previous;
  };
}

/** Throws `BudgetExceeded` when the budget is used up. Cheap enough to call in a loop: the clock is read every 2 048th call. */
export function checkBudget(): void {
  if (deadline === Number.POSITIVE_INFINITY) return;
  if ((++ticks & 2047) !== 0) return;
  if (Date.now() > deadline) throw new BudgetExceeded();
}

/** Like `checkBudget`, but always reads the clock: for coarse loops (one iteration per function, per route). */
export function checkBudgetNow(): void {
  if (deadline !== Number.POSITIVE_INFINITY && Date.now() > deadline) throw new BudgetExceeded();
}
