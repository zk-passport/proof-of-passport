import { ConfigMismatch } from '../errors/index.js';

export const DEFAULT_MAX_PROOF_AGE_SECONDS = 24 * 60 * 60;

const DAY_MS = 24 * 60 * 60 * 1000;

export function checkCircuitTimestamp(
  circuitTimestamp: Date,
  now: Date,
  maxProofAgeSeconds: number
): Array<{ type: ConfigMismatch; message: string }> {
  const issues: Array<{ type: ConfigMismatch; message: string }> = [];

  // an Invalid Date compares false against everything, which would pass both checks below
  if (!Number.isFinite(circuitTimestamp.getTime())) {
    issues.push({
      type: ConfigMismatch.InvalidTimestamp,
      message: 'Circuit timestamp is invalid',
    });
    return issues;
  }

  // clock-skew guard; deliberately not widened by maxProofAgeSeconds
  if (circuitTimestamp > new Date(now.getTime() + DAY_MS)) {
    issues.push({
      type: ConfigMismatch.InvalidTimestamp,
      message: 'Circuit timestamp is in the future',
    });
  }

  // the circuit only carries a date, so age is measured from the end of that local
  // day (next midnight, not +24h, so DST days are right). Compared as numbers: a
  // Date built from a huge tolerance is Invalid and would disable the check.
  const circuitTimestampEOD =
    new Date(
      circuitTimestamp.getFullYear(),
      circuitTimestamp.getMonth(),
      circuitTimestamp.getDate() + 1
    ).getTime() - 1000;
  const pastBound = now.getTime() - maxProofAgeSeconds * 1000;
  if (circuitTimestampEOD < pastBound) {
    issues.push({
      type: ConfigMismatch.InvalidTimestamp,
      message: 'Circuit timestamp is too old',
    });
  }

  return issues;
}
