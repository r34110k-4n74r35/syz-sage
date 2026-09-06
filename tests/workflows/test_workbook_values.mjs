import assert from "node:assert/strict";
import test from "node:test";
import { bugDateValues, dateValue } from "../../scripts/workbook_values.mjs";

test("workbook accepts ISO and retained slash dates without discarding elapsed-time precision", () => {
  const values = bugDateValues({
    first_crash: "2026/07/01",
    last_crash: "2026-07-03",
    fix_time: "2026-08-01",
    close_time: "2026/08/01",
    days_first_to_fix: 31.1,
  });
  assert.deepEqual(values.slice(0, 4).map(value => value.toISOString()), [
    "2026-07-01T00:00:00.000Z", "2026-07-03T00:00:00.000Z",
    "2026-08-01T00:00:00.000Z", "2026-08-01T00:00:00.000Z",
  ]);
  assert.equal(values[4], 31.1);
});

test("impossible, malformed, and missing dates yield empty cells rather than Invalid Date", () => {
  for (const value of [null, undefined, "", "2026-07", "2025-02-29", "2026/13/01", "2026-04-31", "0000-01-01", {}, 20260701]) {
    assert.equal(dateValue(value), null, JSON.stringify(value));
  }
  assert.equal(dateValue("2024/02/29").toISOString(), "2024-02-29T00:00:00.000Z");
  assert.equal(dateValue("0001-01-01").getUTCFullYear(), 1);
});

test("unknown elapsed time stays blank while a known zero interval is retained", () => {
  for (const value of [undefined, null, "", "31.1", NaN, Infinity]) {
    assert.equal(bugDateValues({ days_first_to_fix: value })[4], null);
  }
  assert.equal(bugDateValues({ days_first_to_fix: 0 })[4], 0);
});
