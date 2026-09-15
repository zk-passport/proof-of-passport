import { ConfigMismatch } from '../errors/index.js';

export const DEFAULT_MAX_PROOF_AGE_SECONDS = 24 * 60 * 60;

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Check a proof's circuit date against the accepted window.
 *
 * The circuit records a UTC date with no time, so a proof's age is measured from
 * the end of that UTC day. `maxProofAgeSeconds` therefore buys that tolerance plus
 * up to 24 hours, and it widens the past bound only: a date more than a day ahead
 * of `now` is always rejected as clock skew.
 *
 * @param circuitTimestamp The date carried in the proof's public signals.
 * @param now The instant to judge it against; injected so callers can test it.
 * @param maxProofAgeSeconds How far in the past the circuit date may lie.
 * @returns One issue per failed check, empty when the timestamp is acceptable.
 */
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

  // the circuit only carries a UTC date, so age is measured from the end of that UTC
  // day. Compared as numbers: a Date built from a huge tolerance is Invalid and
  // would disable the check.
  const circuitTimestampEOD =
    Date.UTC(
      circuitTimestamp.getUTCFullYear(),
      circuitTimestamp.getUTCMonth(),
      circuitTimestamp.getUTCDate() + 1
    ) - 1000;
  const pastBound = now.getTime() - maxProofAgeSeconds * 1000;
  if (circuitTimestampEOD < pastBound) {
    issues.push({
      type: ConfigMismatch.InvalidTimestamp,
      message: 'Circuit timestamp is too old',
    });
  }

  return issues;
}
