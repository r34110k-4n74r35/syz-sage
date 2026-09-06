/** Convert analysis date fields to valid UTC spreadsheet dates. */
export function dateValue(value) {
  if (typeof value !== "string") return null;
  const match = /^(\d{4})([-/])(\d{2})\2(\d{2})$/.exec(value.trim());
  if (!match) return null;
  const year = Number(match[1]), month = Number(match[3]), day = Number(match[4]);
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > 31) return null;
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(0, 0, 0, 0);
  // Date would silently roll an impossible date into the following month.
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return null;
  return date;
}

export function bugDateValues(bug) {
  return [
    ...["first_crash", "last_crash", "fix_time", "close_time"].map(field => dateValue(bug[field])),
    // The analyzer uses complete timestamps. Subtracting date-only workbook
    // cells would discard that precision and disagree with the report.
    Number.isFinite(bug.days_first_to_fix) ? bug.days_first_to_fix : null,
  ];
}
