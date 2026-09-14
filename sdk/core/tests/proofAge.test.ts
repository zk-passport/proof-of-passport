import test from 'node:test';
import assert from 'node:assert';
import { SelfBackendVerifier } from '../src/SelfBackendVerifier.js';
import { AttestationId } from '../src/types/types.js';
import { ConfigMismatch } from '../src/errors/index.js';
import { checkCircuitTimestamp, DEFAULT_MAX_PROOF_AGE_SECONDS } from '../src/utils/timestamp.js';

const DAY = 24 * 60 * 60;
const now = new Date(2026, 5, 10, 12, 0, 0);

// mirrors how verify() builds circuitTimestamp: a local-midnight date with no time part
const circuitDate = (daysFromNow: number) =>
  new Date(now.getFullYear(), now.getMonth(), now.getDate() + daysFromNow);

const messages = (circuit: Date, at: Date, tolerance = DEFAULT_MAX_PROOF_AGE_SECONDS) =>
  checkCircuitTimestamp(circuit, at, tolerance).map((i) => i.message);

test('default window: a proof dated yesterday passes', () => {
  assert.deepEqual(messages(circuitDate(-1), now), []);
});

test('default window: a proof dated two days ago fails as too old', () => {
  assert.deepEqual(messages(circuitDate(-2), now), ['Circuit timestamp is too old']);
});

test('default window: a proof dated three days ago fails as too old', () => {
  assert.deepEqual(messages(circuitDate(-3), now), ['Circuit timestamp is too old']);
});

test('default window: exact boundary is the last second of the day after the circuit date', () => {
  const circuit = circuitDate(0);
  const lastValid = new Date(circuit.getTime() + 2 * DAY * 1000 - 1000);
  const firstInvalid = new Date(circuit.getTime() + 2 * DAY * 1000);
  assert.deepEqual(messages(circuit, lastValid), []);
  assert.deepEqual(messages(circuit, firstInvalid), ['Circuit timestamp is too old']);
});

test('a wider tolerance accepts a proof older than the default window', () => {
  assert.deepEqual(messages(circuitDate(-3), now, 90 * DAY), []);
  assert.deepEqual(messages(circuitDate(-89), now, 90 * DAY), []);
});

test('a tolerance shorter than the proof age still rejects it', () => {
  assert.deepEqual(messages(circuitDate(-91), now, 90 * DAY), ['Circuit timestamp is too old']);
  assert.deepEqual(messages(circuitDate(-3), now, 2 * DAY), ['Circuit timestamp is too old']);
});

test('the tolerance never widens the future-skew guard', () => {
  assert.deepEqual(messages(circuitDate(1), now, 90 * DAY), []);
  assert.deepEqual(messages(circuitDate(2), now, 90 * DAY), ['Circuit timestamp is in the future']);
  assert.deepEqual(messages(circuitDate(2), now), ['Circuit timestamp is in the future']);
});

test('issues carry the InvalidTimestamp mismatch type', () => {
  const issues = checkCircuitTimestamp(circuitDate(-3), now, DEFAULT_MAX_PROOF_AGE_SECONDS);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].type, ConfigMismatch.InvalidTimestamp);
});

const configStorage = {
  getConfig: async () => ({ olderThan: 18, excludedCountries: [], ofac: false }),
  getActionId: async () => 'test',
  setConfig: async () => false,
};

const construct = (maxProofAgeSeconds?: number) =>
  new SelfBackendVerifier(
    'test-scope',
    'https://example.com/api/verify',
    true,
    new Map<AttestationId, boolean>([[1, true]]),
    configStorage,
    'uuid',
    maxProofAgeSeconds
  );

test('constructor accepts the tolerance as an optional seventh argument', () => {
  const originalWarn = console.warn;
  console.warn = () => {};
  try {
    assert.ok(construct());
    assert.ok(construct(90 * DAY));
    assert.ok(construct(0));
  } finally {
    console.warn = originalWarn;
  }
});

test('constructor rejects a negative or NaN tolerance', () => {
  const originalWarn = console.warn;
  console.warn = () => {};
  try {
    assert.throws(() => construct(-1), RangeError);
    assert.throws(() => construct(Number.NaN), RangeError);
  } finally {
    console.warn = originalWarn;
  }
});
