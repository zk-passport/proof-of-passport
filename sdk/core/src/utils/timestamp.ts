import { ConfigMismatch } from '../errors/index.js';

export const DEFAULT_MAX_PROOF_AGE_SECONDS = 24 * 60 * 60;

const DAY_MS = 24 * 60 * 60 * 1000;

export function checkCircuitTimestamp(
  circuitTimestamp: Date,
  now: Date,
  maxProofAgeSeconds: number
): Array<{ type: ConfigMismatch; message: string }> {
  const issues: Array<{ type: ConfigMismatch; message: string }> = [];

  // clock-skew guard; deliberately not widened by maxProofAgeSeconds
  if (circuitTimestamp > new Date(now.getTime() + DAY_MS)) {
    issues.push({
      type: ConfigMismatch.InvalidTimestamp,
      message: 'Circuit timestamp is in the future',
    });
  }

  // the circuit only carries a date, so age is measured from the end of that day.
  // Compared as numbers: a Date built from a huge tolerance is Invalid and every
  // comparison against it is false, which would silently disable the check.
  const circuitTimestampEOD = circuitTimestamp.getTime() + DAY_MS - 1000;
  const pastBound = now.getTime() - maxProofAgeSeconds * 1000;
  if (circuitTimestampEOD < pastBound) {
    issues.push({
      type: ConfigMismatch.InvalidTimestamp,
      message: 'Circuit timestamp is too old',
    });
  }

  return issues;
}
