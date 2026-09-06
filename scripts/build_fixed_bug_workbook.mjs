import fs from "node:fs/promises";
import path from "node:path";
import { writablePath } from "./project_paths.mjs";
import { bugDateValues } from "./workbook_values.mjs";

const [analysisPath, requestedOutput, requestedPreviews] = process.argv.slice(2);
if (!analysisPath || !requestedOutput || !requestedPreviews) {
  throw new Error("usage: build_fixed_bug_workbook.mjs ANALYSIS_JSON OUTPUT_XLSX PREVIEW_DIR");
}
const outputPath = await writablePath(requestedOutput);
const previewDir = await writablePath(requestedPreviews);
async function buildWorkbook() {
  const { SpreadsheetFile, Workbook } = await import("@oai/artifact-tool");

  const analysis = JSON.parse(await fs.readFile(await writablePath(analysisPath), "utf8"));
  const bugs = analysis.bugs;
  const hunks = analysis.hunks;
  const manifest = analysis.manifest;
  const completeness = analysis.completeness || {};
  const baseline = analysis.completeness_baseline || {};
  const supplementalRecovered = analysis.supplemental_fix_resolution?.resolved_fix_records || 0;
  const unresolvedCount = bugs.filter(b => b.distance == null).length;
  const inflatedCount = bugs.filter(b => b.distance != null && b.distance_min != null && b.distance > b.distance_min).length;
  const workbook = Workbook.create();

  const COLORS = {
    navy: "#17324D", teal: "#0F766E", blue: "#2563EB", cyan: "#DFF4F2",
    pale: "#F4F7FA", white: "#FFFFFF", ink: "#17212B", muted: "#5E6B78",
    line: "#CBD5E1", red: "#B42318", amber: "#B54708", green: "#087A55",
    d0: "#D1FAE5", d1: "#DCFCE7", d2: "#DBEAFE", d3: "#EDE9FE",
    d4: "#FEF3C7", d5: "#FEE2E2",
  };

  function colLetter(n) {
    let s = "";
    while (n > 0) { n--; s = String.fromCharCode(65 + (n % 26)) + s; n = Math.floor(n / 26); }
    return s;
  }

  function setTitle(sheet, range, text) {
    range.merge();
    range.values = [[text]];
    range.format = {
      fill: COLORS.navy,
      font: { name: "Aptos Display", size: 18, bold: true, color: COLORS.white },
      verticalAlignment: "center", horizontalAlignment: "left",
    };
    range.format.rowHeight = 34;
  }

  function styleHeader(range) {
    range.format = {
      fill: COLORS.teal,
      font: { name: "Aptos", size: 10, bold: true, color: COLORS.white },
      verticalAlignment: "center", horizontalAlignment: "left", wrapText: true,
      borders: { preset: "outside", style: "thin", color: COLORS.line },
    };
    range.format.rowHeight = 30;
  }

  function styleSection(range) {
    range.format = {
      fill: COLORS.cyan,
      font: { name: "Aptos", size: 11, bold: true, color: COLORS.navy },
      borders: { bottom: { style: "medium", color: COLORS.teal } },
    };
  }

  function baseSheet(sheet) {
    sheet.showGridLines = false;
  }

  function setWidths(sheet, specs, lastRow) {
    for (const [col, width] of specs) {
      sheet.getRange(`${col}1:${col}${lastRow}`).format.columnWidth = width;
    }
  }

  function addDistanceFormats(range) {
    const configs = [
      ["D0", COLORS.d0], ["D1", COLORS.d1], ["D2", COLORS.d2],
      ["D3", COLORS.d3], ["D4", COLORS.d4], ["D5", COLORS.d5],
    ];
    for (const [text, fill] of configs) {
      range.conditionalFormats.add("beginsWith", { text, format: { fill, font: { bold: true, color: COLORS.ink } } });
    }
  }

  const readme = workbook.worksheets.add("README");
  baseSheet(readme);
  setTitle(readme, readme.getRange("A1:H1"), "Syzbot Fixed-Bug Crash–Fix Distance Study");
  readme.getRange("A3:H3").merge();
  readme.getRange("A3").values = [[`Analysis cohort: ${bugs.length.toLocaleString()} bugs from the live Syzbot upstream/fixed listing with a downloaded crash report and at least one downloaded patch. Reproducer files and fields are not used.`]];
  readme.getRange("A3:H3").format = { fill: COLORS.pale, font: { name: "Aptos", size: 11, bold: true, color: COLORS.navy }, wrapText: true };
  readme.getRange("A5:H5").merge();
  readme.getRange("A5").values = [["Study definitions"]];
  styleSection(readme.getRange("A5:H5"));
  readme.getRange("A6:B10").values = [
    ["Crash site (CS)", "Manifestation source location. Sanitizer runtime frames are skipped; explicit access locations and symbolized application frames are preferred. Other-task and unwind traces cannot supply missing crash coordinates."],
    ["Fix site (FS)", "Changed source hunks in every available fix commit. The bug-level structural grade is the maximum hunk grade, as requested."],
    ["Structural D", "D0 exact/adjacent changed statement; D1 same function; D2 same file; D3 same component; D4 same subsystem; D5 cross-subsystem."],
    ["Stack S", "Frame-edge distance from CS to the nearest extracted fixed function on the manifestation stack; ∞ means off-stack; unknown means the FS function or stack was unavailable."],
    ["Temporal Δt", "Within the same syscall, across syscalls in one session, unbounded, not applicable, or not determined; alloc/free stacks and task/context changes are anchors."],
  ];
  styleHeader(readme.getRange("A6:A10"));
  readme.getRange("B6:B10").format = { wrapText: true, verticalAlignment: "top", font: { name: "Aptos", size: 10, color: COLORS.ink } };
  readme.getRange("A12:H12").merge(); readme.getRange("A12").values = [["Sanitizer-aware CS selection"]]; styleSection(readme.getRange("A12:H12"));
  readme.getRange("A13:B18").values = [
    ["KASAN/KMSAN/KFENCE", "Prefer an explicit access coordinate, otherwise match the normalized title function to the symbolized manifestation stack. Allocation, free, and origin frames cannot supply missing crash coordinates."],
    ["UBSAN", "Use the explicit file:line:column expression location; record a function only when the same coordinate is symbolized."],
    ["KCSAN", "Record both conflicting access functions/locations; the primary CS is the first normalized access site."],
    ["BUG/WARN/lockdep", "Prefer explicit BUG/WARNING source locations or the normalized title function on the symbolized stack."],
    ["Ordinary oops", "Match the kernel RIP/PC symbol to a symbolized source frame; user-space RIP is ignored."],
    ["D0 tolerance", "A changed old line or pure-insertion anchor within ±2 lines of CS counts as D0 to cover an adjacent guard and small parent/report line drift."],
  ];
  styleHeader(readme.getRange("A13:A18"));
  readme.getRange("B13:B18").format = { wrapText: true, verticalAlignment: "top", font: { name: "Aptos", size: 10, color: COLORS.ink } };
  readme.getRange("A20:H20").merge(); readme.getRange("A20").values = [["Important limitations"]]; styleSection(readme.getRange("A20:H20"));
  readme.getRange("A21:H25").merge(true);
  readme.getRange("A21:A25").values = [
    ["• D4/D5 use a documented path taxonomy as a MAINTAINERS proxy because historical kernel trees/MAINTAINERS files are not in this project. Validate these two grades against each fix commit's historical tree before publication-level claims."],
    ["• Function extraction uses git hunk headers and nearby definitions. Global initializers, labels, Kconfig, and some macro hunks leave FS function unknown."],
    ["• Δt is a coarse report-derived annotation, not dynamic provenance. “Not determined” is retained rather than imputed."],
    ["• Data-flow hops T are not computed because this corpus has no taint-analysis results."],
    [`• ${unresolvedCount.toLocaleString()} included report${unresolvedCount === 1 ? "" : "s"} lack${unresolvedCount === 1 ? "s" : ""} a fully resolvable structural grade; these records are isolated on the QC sheet rather than silently excluded.`],
  ];
  readme.getRange("A21:H25").format = { wrapText: true, font: { name: "Aptos", size: 10, color: COLORS.ink }, fill: "#FFF8E7" };
  readme.getRange("A27:H27").merge(); readme.getRange("A27").values = [["Workbook map"]]; styleSection(readme.getRange("A27:H27"));
  readme.getRange("A28:B36").values = [
    ["Definitions", "Complete study framework: CS/FS, D0–D5, S, Δt, T, annotation syntax, and expected class correlations."],
    ["Dashboard", "Formula-driven totals, distributions, and compact charts."],
    ["Bugs", "One row per included Syzbot bug; primary classifications and D/S/Δt annotation."],
    ["Fix Hunks", "One row per source hunk (or non-source fallback); the audit trail for maximum distance."],
    ["Evidence", "Classification evidence, stack/temporal reasons, source URLs, and kernel-build metadata."],
    ["Examples", "Representative patterns across D0–D5."],
    ["Taxonomy", "Bug and patch classification definitions."],
    ["QC", "Low-confidence/unresolved/manual-review records and quality counts."],
    ["Cohort Manifest", "All local fixed bug records with inclusion/exclusion criteria."],
  ];
  styleHeader(readme.getRange("A28:A36"));
  readme.getRange("B28:B36").format = { wrapText: true, font: { name: "Aptos", size: 10, color: COLORS.ink } };
  setWidths(readme, [["A", 28], ["B", 96], ["C", 4], ["D", 4], ["E", 4], ["F", 4], ["G", 4], ["H", 4]], 36);
  readme.freezePanes.freezeRows(3);

  const definitions = workbook.worksheets.add("Definitions");
  baseSheet(definitions);
  setTitle(definitions, definitions.getRange("A1:H1"), "Complete Crash–Fix Distance Framework");
  definitions.getRange("A2:H2").merge();
  definitions.getRange("A2").values = [["This sheet records the full owner-specified conceptual definition and the operational interpretation used in the study."]];
  definitions.getRange("A2:H2").format = { fill: COLORS.pale, font: { name: "Aptos", size: 10, color: COLORS.muted }, wrapText: true };
  definitions.getRange("A4:H4").merge(); definitions.getRange("A4").values = [["Basic definitions"]]; styleSection(definitions.getRange("A4:H4"));
  definitions.getRange("A5:C8").values = [
    ["Concept", "Definition", "Study implementation"],
    ["Crash site (CS)", "Manifestation point of the fault. Take the kernel RIP/PC or detector-specific manifestation frame and symbolize it to file:line plus enclosing function.", "Sanitizer/runtime helpers and user-space RIP are skipped. UBSAN expression locations and normalized detector frames may be more authoritative than the first printed RIP."],
    ["Fix site (FS)", "Root-cause location represented by the fix-commit diff hunks. For a multi-hunk or multi-commit fix, compute each hunk distance and report the maximum.", "Every available source hunk is retained on Fix Hunks. D(max) is primary; D(min) is retained as a sensitivity annotation."],
    ["Distance", "Deviation between CS and FS along structural, stack, and temporal axes.", "Structural D is the primary grade; S and Δt are orthogonal annotations. T remains optional because it requires taint analysis."],
  ];
  styleHeader(definitions.getRange("A5:C5"));
  definitions.getRange("A6:C8").format = { font: { name: "Aptos", size: 10, color: COLORS.ink }, wrapText: true, verticalAlignment: "top" };

  definitions.getRange("A9:H9").merge(); definitions.getRange("A9").values = [["Primary grading: structural distance D0–D5"]]; styleSection(definitions.getRange("A9:H9"));
  definitions.getRange("A10:D16").values = [
    ["Level", "Name", "Definition", "Typical bug pattern"],
    ["D0", "Coincident", "The fix hunk touches the exact crashing line/statement. The implementation accepts an adjacent insertion anchor within ±2 lines.", "Missing NULL check immediately before a dereference; off-by-one at the access."],
    ["D1", "Intra-function", "FS is in the same function as CS, but on different lines.", "Missing lock or length check elsewhere in the crashing function."],
    ["D2", "Intra-file", "FS is in another function within the same compilation unit/source file.", "Handler manifests the crash; same-file helper produces the invalid state."],
    ["D3", "Intra-component", "CS and FS cross files inside one component, module, driver, or filesystem implementation.", "Driver entry point manifests; another file's state machine is repaired."],
    ["D4", "Intra-subsystem", "CS and FS are in different components covered by the same subsystem/MAINTAINERS scope.", "Generic VFS or network code manifests a defect produced by a specific component."],
    ["D5", "Cross-subsystem", "CS and FS belong to different subsystem/MAINTAINERS scopes.", "Classic victim site: allocator, formatter, or generic core reports damage caused elsewhere."],
  ];
  styleHeader(definitions.getRange("A10:D10")); addDistanceFormats(definitions.getRange("A11:A16"));
  definitions.getRange("A11:D16").format = { font: { name: "Aptos", size: 10, color: COLORS.ink }, wrapText: true, verticalAlignment: "top" };

  definitions.getRange("A18:H18").merge(); definitions.getRange("A18").values = [["Orthogonal annotation axes"]]; styleSection(definitions.getRange("A18:H18"));
  definitions.getRange("A19:D24").values = [
    ["Axis", "Meaning", "Values/buckets", "Interpretation"],
    ["Stack distance S", "Number of frames between the crashing frame and nearest fixed function in the manifestation stack.", "S=0; finite S>0; S=∞ off-stack; unknown.", "S=0 places a fixed function on the crash frame. Prior work suggests most root causes are on-stack, making S=∞ a strong localization warning."],
    ["Temporal distance Δt", "When corruption/state production occurs relative to manifestation.", "within the same syscall; across syscalls within one session; unbounded; not applicable; not determined.", "KASAN alloc/free stacks, origin stacks, task IDs, and async contexts provide anchors. Unsupported cases remain undetermined."],
    ["Data-flow hops T", "Number of assignments/copies from bad-value production to consumption.", "direct; 1–3 hops; >3 hops.", "Optional and not computed in this corpus because a taint-analysis result is required."],
    ["Full annotation", "Compact conjunction of independent axes.", "Example: D4/S=∞/Δt=unbounded", "Cross-component/subsystem manifestation, fixed function absent from stack, and temporally decoupled corruption."],
    ["Victim-site signature", "Strongest available manifestation/root-cause separation.", "D4 or D5 + S=∞ + Δt=unbounded", "Crash site is best treated as the victim; cluster by producer, object lifetime, alloc/free stacks, and fix semantics."],
  ];
  styleHeader(definitions.getRange("A19:D19"));
  definitions.getRange("A20:D24").format = { font: { name: "Aptos", size: 10, color: COLORS.ink }, wrapText: true, verticalAlignment: "top" };

  definitions.getRange("A26:H26").merge(); definitions.getRange("A26").values = [["Expected correlation with bug classes"]]; styleSection(definitions.getRange("A26:H26"));
  definitions.getRange("A27:D30").values = [
    ["Bug class", "Expected D", "Expected S/Δt", "Deduplication implication"],
    ["Logic bugs: missing checks, wrong conditions", "Mostly D0–D1", "Usually S=0; Δt within the detecting operation", "Crash title/top-frame identity is often a useful approximation of root cause."],
    ["Refcount and locking bugs", "Mostly D1–D3", "Fixed function often on-stack, but IRQ/process/async context can increase S", "Include component, context, and synchronization/lifetime features."],
    ["Memory corruption: OOB write, UAF", "Concentrated D3–D5", "Often S=∞ and Δt=unbounded", "Treat crash as a victim; prioritize alloc/free stacks, producer subsystem, object type, and fix-root features."],
  ];
  styleHeader(definitions.getRange("A27:D27"));
  definitions.getRange("A28:D30").format = { font: { name: "Aptos", size: 10, color: COLORS.ink }, wrapText: true, verticalAlignment: "top" };

  definitions.getRange("A32:H35").merge(true);
  definitions.getRange("A32:A35").values = [
    ["Detector caution: for KASAN/KMSAN/KFENCE the first RIP is commonly detector machinery. Select the normalized invalid-access/consumption frame. For UBSAN use the explicit expression site; for KCSAN retain both conflicting accesses."],
    ["Ground-truth caution: the fix commit is treated as the root-cause ground truth, consistent with kernel duplicate-bug research, but large cleanups and multi-purpose patches can broaden D(max). D(min) and the hunk table expose this sensitivity."],
    ["Subsystem caution: D4/D5 in this artifact use a path taxonomy as a historical MAINTAINERS proxy. Validate exact maintainer-entry membership against the fix revision before publication claims."],
    ["Axes are orthogonal: a D0 repair can still have unbounded Δt, and a D5 repair can occasionally appear on-stack. Interpret the full annotation rather than inferring one axis from another."],
  ];
  definitions.getRange("A32:H35").format = { fill: "#FFF8E7", font: { name: "Aptos", size: 10, color: COLORS.ink }, wrapText: true, verticalAlignment: "center" };
  setWidths(definitions, [["A",26],["B",38],["C",78],["D",72],["E",4],["F",4],["G",4],["H",4]], 35);
  definitions.freezePanes.freezeRows(4);

  const bugHeaders = [
    "Bug key", "Title", "Syzbot URL", "Status", "First crash", "Last crash", "Fix time", "Close time", "Days first→fix",
    "Detector", "Bug family", "Bug type", "Access", "CS function", "CS path", "CS line", "CS location", "CS component", "CS subsystem",
    "CS selection rule", "CS confidence", "Secondary CS function", "Secondary CS location", "Fix commit count", "Fix hashes", "Fix commit URLs",
    "Patch title(s)", "Fix path(s)", "Fix function(s)", "Source hunk count", "Patch additions", "Patch deletions", "Patch type", "Patch action",
    "Patch class confidence", "Structural D max", "Distance label", "Structural D min", "Farthest FS location", "Farthest FS component",
    "Farthest FS subsystem", "Distance reason", "Distance confidence", "Stack distance S", "Temporal distance Δt", "Temporal confidence",
    "Full annotation", "Data-flow hops T", "Review status", "QC flags", "Report path", "Fix hash source",
  ];
  const bugIndex = Object.fromEntries(bugHeaders.map((h, i) => [h, i + 1]));
  const bugCol = h => colLetter(bugIndex[h]);
  const bugRows = bugs.map(b => [
    b.bug_key, b.title, b.bug_url, b.status, ...bugDateValues(b),
    b.detector, b.bug_family, b.bug_type, b.access_mode, b.cs_function, b.cs_path, b.cs_line, b.cs_location, b.cs_component, b.cs_subsystem,
    b.cs_strategy, b.cs_confidence, b.cs_secondary_function, b.cs_secondary_location, b.fix_commit_count, b.fix_hashes, b.fix_commit_urls,
    b.patch_titles, b.fix_paths, b.fix_functions, b.fix_hunk_count, b.patch_additions, b.patch_deletions, b.patch_type, b.patch_action,
    b.patch_class_confidence, b.distance, b.distance_label, b.distance_min, b.farthest_fs_location, b.farthest_fs_component,
    b.farthest_fs_subsystem, b.distance_reason, b.distance_confidence, b.stack_distance, b.temporal_distance, b.temporal_confidence,
    null, b.data_flow_hops_T, b.review_status, b.qc_flags, b.report_path, b.fix_hash_source,
  ]);
  const bugSheet = workbook.worksheets.add("Bugs"); baseSheet(bugSheet);
  const bugLastRow = bugRows.length + 1, bugLastCol = colLetter(bugHeaders.length);
  bugSheet.getRange(`A1:${bugLastCol}${bugLastRow}`).values = [bugHeaders, ...bugRows];
  styleHeader(bugSheet.getRange(`A1:${bugLastCol}1`));
  bugSheet.getRange(`${bugCol("Full annotation")}2`).formulas = [[`=IF(${bugCol("Distance label")}2="Unresolved","Unresolved",LEFT(${bugCol("Distance label")}2,2)&"/S="&${bugCol("Stack distance S")}2&"/Δt="&${bugCol("Temporal distance Δt")}2)`]];
  bugSheet.getRange(`${bugCol("Full annotation")}2:${bugCol("Full annotation")}${bugLastRow}`).fillDown();
  bugSheet.getRange(`${bugCol("First crash")}2:${bugCol("Close time")}${bugLastRow}`).format.numberFormat = "yyyy-mm-dd";
  bugSheet.getRange(`${bugCol("Days first→fix")}2:${bugCol("Days first→fix")}${bugLastRow}`).format.numberFormat = "0.0";
  bugSheet.getRange(`${bugCol("Structural D max")}2:${bugCol("Structural D min")}${bugLastRow}`).format.numberFormat = "0";
  bugSheet.getRange(`A2:${bugLastCol}${bugLastRow}`).format.font = { name: "Aptos", size: 9, color: COLORS.ink };
  bugSheet.getRange(`B2:B${bugLastRow}`).format.wrapText = true;
  bugSheet.getRange(`${bugCol("Patch title(s)")}2:${bugCol("Fix function(s)")}${bugLastRow}`).format.wrapText = true;
  bugSheet.getRange(`${bugCol("Distance label")}2:${bugCol("Distance label")}${bugLastRow}`).format.horizontalAlignment = "center";
  addDistanceFormats(bugSheet.getRange(`${bugCol("Distance label")}2:${bugCol("Distance label")}${bugLastRow}`));
  bugSheet.getRange(`${bugCol("Review status")}2:${bugCol("Review status")}${bugLastRow}`).conditionalFormats.add("containsText", { text: "Manual", format: { fill: COLORS.d4, font: { bold: true, color: COLORS.amber } } });
  const bugTable = bugSheet.tables.add(`A1:${bugLastCol}${bugLastRow}`, true, "BugsTable"); bugTable.style = "TableStyleMedium2";
  bugSheet.freezePanes.freezeRows(1); bugSheet.freezePanes.freezeColumns(2);
  setWidths(bugSheet, [
    ["A", 25], ["B", 48], ["C", 42], ["D", 20], ["E", 13], ["F", 13], ["G", 13], ["H", 13], ["I", 14],
    ["J", 18], ["K", 20], ["L", 30], ["M", 12], ["N", 26], ["O", 42], ["P", 10], ["Q", 46], ["R", 28], ["S", 20],
    ["T", 40], ["U", 13], ["V", 24], ["W", 42], ["X", 12], ["Y", 38], ["Z", 52], ["AA", 54], ["AB", 54], ["AC", 48],
    ["AD", 12], ["AE", 12], ["AF", 12], ["AG", 30], ["AH", 52], ["AI", 15], ["AJ", 13], ["AK", 22], ["AL", 13],
    ["AM", 56], ["AN", 30], ["AO", 22], ["AP", 54], ["AQ", 15], ["AR", 14], ["AS", 36], ["AT", 15], ["AU", 42],
    ["AV", 34], ["AW", 24], ["AX", 62], ["AY", 48], ["AZ", 28],
  ], bugLastRow);

  const hunkHeaders = ["Bug key", "Bug title", "Commit hash", "Patch title", "Hunk #", "Fix path", "FS function(s)", "Old start", "Old count", "New start", "New count", "Changed old lines", "Insertion anchors", "Additions", "Deletions", "Component", "Subsystem", "Hunk D", "Hunk distance label", "Distance reason", "Confidence", "CS function", "CS location", "Hunk context"];
  const hunkRows = hunks.map(h => [
    h.bug_key, h.bug_title, h.commit_hash, h.patch_title, h.hunk_index_for_bug, h.path, h.function_text,
    h.old_start, h.old_count, h.new_start, h.new_count, h.changed_old_line_text, h.insertion_anchor_text,
    h.additions, h.deletions, h.component, h.subsystem, h.distance, h.distance_label, h.distance_reason,
    h.distance_confidence, h.cs_function, h.cs_location, h.context,
  ]);
  const hunkSheet = workbook.worksheets.add("Fix Hunks"); baseSheet(hunkSheet);
  const hunkLastRow = hunkRows.length + 1, hunkLastCol = colLetter(hunkHeaders.length);
  hunkSheet.getRange(`A1:${hunkLastCol}${hunkLastRow}`).values = [hunkHeaders, ...hunkRows];
  styleHeader(hunkSheet.getRange(`A1:${hunkLastCol}1`));
  hunkSheet.getRange(`A2:${hunkLastCol}${hunkLastRow}`).format.font = { name: "Aptos", size: 9, color: COLORS.ink };
  addDistanceFormats(hunkSheet.getRange(`S2:S${hunkLastRow}`));
  const hunkTable = hunkSheet.tables.add(`A1:${hunkLastCol}${hunkLastRow}`, true, "FixHunksTable"); hunkTable.style = "TableStyleMedium4";
  hunkSheet.freezePanes.freezeRows(1); hunkSheet.freezePanes.freezeColumns(2);
  setWidths(hunkSheet, [["A",25],["B",46],["C",42],["D",52],["E",10],["F",44],["G",34],["H",11],["I",10],["J",11],["K",10],["L",32],["M",32],["N",10],["O",10],["P",30],["Q",20],["R",10],["S",22],["T",56],["U",13],["V",28],["W",46],["X",44]], hunkLastRow);

  const evidenceHeaders = ["Bug key", "Title", "Bug-class evidence", "CS evidence", "Patch-class evidence", "S reason", "Δt reason", "Report URL", "Fix commit URL(s)", "Kernel repo", "Kernel commit", "Fix hash source"];
  const evidenceRows = bugs.map(b => [b.bug_key, b.title, b.bug_class_evidence, b.cs_evidence, b.patch_class_evidence, b.stack_distance_reason, b.temporal_reason, b.report_url, b.fix_commit_urls, b.kernel_repo, b.kernel_commit, b.fix_hash_source]);
  const evidenceSheet = workbook.worksheets.add("Evidence"); baseSheet(evidenceSheet);
  const evidenceLastRow = evidenceRows.length + 1, evidenceLastCol = colLetter(evidenceHeaders.length);
  evidenceSheet.getRange(`A1:${evidenceLastCol}${evidenceLastRow}`).values = [evidenceHeaders, ...evidenceRows];
  styleHeader(evidenceSheet.getRange(`A1:${evidenceLastCol}1`));
  evidenceSheet.getRange(`A2:${evidenceLastCol}${evidenceLastRow}`).format = { font: { name: "Aptos", size: 9, color: COLORS.ink }, wrapText: true, verticalAlignment: "top" };
  const evidenceTable = evidenceSheet.tables.add(`A1:${evidenceLastCol}${evidenceLastRow}`, true, "EvidenceTable"); evidenceTable.style = "TableStyleMedium2";
  evidenceSheet.freezePanes.freezeRows(1); evidenceSheet.freezePanes.freezeColumns(2);
  setWidths(evidenceSheet, [["A",25],["B",46],["C",66],["D",66],["E",52],["F",54],["G",54],["H",55],["I",55],["J",48],["K",42],["L",28]], evidenceLastRow);

  const dashboard = workbook.worksheets.add("Dashboard"); baseSheet(dashboard);
  setTitle(dashboard, dashboard.getRange("A1:M1"), "Crash–Fix Distance Dashboard");
  dashboard.getRange("A2:M2").merge(); dashboard.getRange("A2").values = [[`Formula-driven summary of the ${bugs.length.toLocaleString()}-bug report-and-patch cohort. Primary D uses the maximum across source hunks; D4/D5 are path-based MAINTAINERS proxies.`]];
  dashboard.getRange("A2:M2").format = { fill: COLORS.pale, font: { name: "Aptos", size: 10, color: COLORS.muted }, wrapText: true };
  const cards = [["A3:C3","A4:C6","Included bugs"],["D3:F3","D4:F6","Structurally resolved"],["G3:I3","G4:I6","D3–D5 among resolved"],["J3:L3","J4:L6","Off-stack among known S"]];
  for (const [labelRange, valueRange, label] of cards) {
    dashboard.getRange(labelRange).merge(); dashboard.getRange(labelRange.split(":")[0]).values = [[label]];
    dashboard.getRange(labelRange).format = { fill: COLORS.teal, font: { name: "Aptos", size: 10, bold: true, color: COLORS.white }, horizontalAlignment: "center" };
    dashboard.getRange(valueRange).merge();
    dashboard.getRange(valueRange).format = { fill: COLORS.cyan, font: { name: "Aptos Display", size: 22, bold: true, color: COLORS.navy }, horizontalAlignment: "center", verticalAlignment: "center", borders: { preset: "outside", style: "thin", color: COLORS.line } };
  }
  const nRange = `'Bugs'!$A$2:$A$${bugLastRow}`;
  const dRange = `'Bugs'!$${bugCol("Structural D max")}$2:$${bugCol("Structural D max")}$${bugLastRow}`;
  const dlRange = `'Bugs'!$${bugCol("Distance label")}$2:$${bugCol("Distance label")}$${bugLastRow}`;
  const sRange = `'Bugs'!$${bugCol("Stack distance S")}$2:$${bugCol("Stack distance S")}$${bugLastRow}`;
  const famRange = `'Bugs'!$${bugCol("Bug family")}$2:$${bugCol("Bug family")}$${bugLastRow}`;
  const patchRange = `'Bugs'!$${bugCol("Patch type")}$2:$${bugCol("Patch type")}$${bugLastRow}`;
  const typeRange = `'Bugs'!$${bugCol("Bug type")}$2:$${bugCol("Bug type")}$${bugLastRow}`;
  const tempRange = `'Bugs'!$${bugCol("Temporal distance Δt")}$2:$${bugCol("Temporal distance Δt")}$${bugLastRow}`;
  const csConfRange = `'Bugs'!$${bugCol("CS confidence")}$2:$${bugCol("CS confidence")}$${bugLastRow}`;
  const dConfRange = `'Bugs'!$${bugCol("Distance confidence")}$2:$${bugCol("Distance confidence")}$${bugLastRow}`;
  const hunkCountRange = `'Bugs'!$${bugCol("Source hunk count")}$2:$${bugCol("Source hunk count")}$${bugLastRow}`;
  dashboard.getRange("A4").formulas = [[`=COUNTA(${nRange})`]];
  dashboard.getRange("D4").formulas = [[`=COUNT(${dRange})/COUNTA(${nRange})`]];
  dashboard.getRange("G4").formulas = [[`=COUNTIF(${dRange},">=3")/COUNT(${dRange})`]];
  dashboard.getRange("J4").formulas = [[`=COUNTIF(${sRange},"∞")/(COUNTA(${sRange})-COUNTIF(${sRange},"unknown"))`]];
  dashboard.getRange("D4:L6").format.numberFormat = "0.0%";
  dashboard.getRange("A8:M8").merge(); dashboard.getRange("A8").values = [["Primary structural distribution"]]; styleSection(dashboard.getRange("A8:M8"));
  dashboard.getRange("A9:C16").values = [["Grade","Bugs","Share"],["D0",null,null],["D1",null,null],["D2",null,null],["D3",null,null],["D4",null,null],["D5",null,null],["Unresolved",null,null]];
  styleHeader(dashboard.getRange("A9:C9"));
  for (let row = 10; row <= 16; row++) {
    if (row === 16) dashboard.getRange(`B${row}`).formulas = [[`=COUNTA(${nRange})-COUNT(${dRange})`]];
    else dashboard.getRange(`B${row}`).formulas = [[`=COUNTIF(${dRange},${row - 10})`]];
    dashboard.getRange(`C${row}`).formulas = [[`=B${row}/$A$4`]];
  }
  dashboard.getRange("C10:C16").format.numberFormat = "0.0%"; addDistanceFormats(dashboard.getRange("A10:A15"));
  const dChart = dashboard.charts.add("bar", dashboard.getRange("A9:B15"));
  dChart.title = "Most fixes are structurally non-local (D3–D5)"; dChart.hasLegend = false; dChart.setPosition("E9", "M24");
  dChart.xAxis = { numberFormatCode: "0" }; dChart.yAxis = { axisType: "textAxis" };

  const families = ["Invariant violation", "Memory safety", "Concurrency", "Liveness", "Undefined behavior", "Kernel fault", "Resource/lifetime", "Memory disclosure"];
  dashboard.getRange("A19:D27").values = [["Bug family","Bugs","D3–D5","Far share resolved"], ...families.map(x => [x,null,null,null])];
  styleHeader(dashboard.getRange("A19:D19"));
  for (let i = 0; i < families.length; i++) {
    const row = 20 + i;
    dashboard.getRange(`B${row}`).formulas = [[`=COUNTIF(${famRange},A${row})`]];
    dashboard.getRange(`C${row}`).formulas = [[`=COUNTIFS(${famRange},A${row},${dRange},">=3")`]];
    dashboard.getRange(`D${row}`).formulas = [[`=IF(COUNTIFS(${famRange},A${row},${dRange},"<>")=0,0,C${row}/COUNTIFS(${famRange},A${row},${dRange},"<>"))`]];
  }
  dashboard.getRange("D20:D27").format.numberFormat = "0.0%";
  const fChart = dashboard.charts.add("bar", dashboard.getRange("A19:B27"));
  fChart.title = "Bug families in the included cohort"; fChart.hasLegend = false; fChart.setPosition("E26", "M42");
  fChart.xAxis = { numberFormatCode: "0" }; fChart.yAxis = { axisType: "textAxis" };

  const patchTypes = ["Validation/guard", "Synchronization/ordering", "Lifetime/resource management", "Logic/control-flow correction", "Initialization/state correction", "Bounds/size correction", "API/protocol contract", "Arithmetic/type correction", "Error-path handling", "Refcount/accounting correction"];
  dashboard.getRange("A30:D40").values = [["Patch type","Bugs","D3–D5","Far share resolved"], ...patchTypes.map(x => [x,null,null,null])];
  styleHeader(dashboard.getRange("A30:D30"));
  for (let i = 0; i < patchTypes.length; i++) {
    const row = 31 + i;
    dashboard.getRange(`B${row}`).formulas = [[`=COUNTIF(${patchRange},A${row})`]];
    dashboard.getRange(`C${row}`).formulas = [[`=COUNTIFS(${patchRange},A${row},${dRange},">=3")`]];
    dashboard.getRange(`D${row}`).formulas = [[`=IF(COUNTIFS(${patchRange},A${row},${dRange},"<>")=0,0,C${row}/COUNTIFS(${patchRange},A${row},${dRange},"<>"))`]];
  }
  dashboard.getRange("D31:D40").format.numberFormat = "0.0%";
  dashboard.getRange("A43:D48").values = [["UAF Δt","Bugs","Share of UAF","Interpretation"],["within the same syscall",null,null,"Free/access anchored to one syscall"],["across syscalls within one session",null,null,"Same task, different syscall frames"],["unbounded",null,null,"Different task/async context or distinct free stack"],["not determined",null,null,"No usable free-stack anchor"],["Total UAF",null,null,"Title/report classified UAF"]];
  styleHeader(dashboard.getRange("A43:D43"));
  for (let row = 44; row <= 47; row++) dashboard.getRange(`B${row}`).formulas = [[`=COUNTIFS(${typeRange},"Use-after-free (read)",${tempRange},A${row})+COUNTIFS(${typeRange},"Use-after-free (write)",${tempRange},A${row})+COUNTIFS(${typeRange},"Use-after-free",${tempRange},A${row})`]];
  dashboard.getRange("B48").formulas = [[`=COUNTIF(${typeRange},"Use-after-free (read)")+COUNTIF(${typeRange},"Use-after-free (write)")+COUNTIF(${typeRange},"Use-after-free")`]];
  for (let row = 44; row <= 47; row++) dashboard.getRange(`C${row}`).formulas = [[`=IF($B$48=0,0,B${row}/$B$48)`]];
  dashboard.getRange("C44:C47").format.numberFormat = "0.0%";
  dashboard.getRange("A50:M52").merge(true); dashboard.getRange("A50:A52").values = [
    ["Reading the dashboard: structural D answers where the manifestation sits relative to every fix hunk; S answers whether the fixed function is visible on the manifestation stack; Δt uses report anchors and deliberately leaves unsupported cases undetermined."],
    [`Sensitivity: the Bugs sheet also retains Structural D min. ${inflatedCount.toLocaleString()} bugs have max > min, so the required maximum-hunk rule materially shifts the headline distribution upward.`],
    ["Publication caution: D0–D3 are based on exact function/file/path relations. D4/D5 need historical MAINTAINERS validation before being treated as exact maintainer-entry boundaries."],
  ];
  dashboard.getRange("A50:M52").format = { fill: "#FFF8E7", font: { name: "Aptos", size: 10, color: COLORS.ink }, wrapText: true, verticalAlignment: "center" };
  setWidths(dashboard, [["A",30],["B",12],["C",14],["D",34],["E",4],["F",14],["G",14],["H",14],["I",14],["J",14],["K",14],["L",14],["M",4]], 52);
  dashboard.freezePanes.freezeRows(2);

  const evaluation = workbook.worksheets.add("Evaluation"); baseSheet(evaluation);
  setTitle(evaluation, evaluation.getRange("A1:J1"), "Cross-Axis Evaluation and Completeness");
  evaluation.getRange("A2:J2").merge(); evaluation.getRange("A2").values = [["Formula-driven tests of the study framework. Operational groups are explicit proxies, not manually adjudicated causal labels."]];
  evaluation.getRange("A2:J2").format = { fill: COLORS.pale, font: { name: "Aptos", size: 10, color: COLORS.muted }, wrapText: true };

  evaluation.getRange("A4:J4").values = [["Framework group","Operationalization","Bugs","Resolved D","D0–D1","Local share resolved","D3–D5","Far share resolved","S=∞","Δt unbounded"]]; styleHeader(evaluation.getRange("A4:J4"));
  const groupSpecs = [
    {name:"All bugs", description:"Entire included report-and-patch cohort", range:null, values:[]},
    {name:"Logic/condition repair proxy", description:"Validation, control-flow, bounds/size, or arithmetic/type patch", range:patchRange, values:["Validation/guard","Logic/control-flow correction","Bounds/size correction","Arithmetic/type correction"]},
    {name:"Refcount/locking proxy", description:"Synchronization/ordering or refcount/accounting patch", range:patchRange, values:["Synchronization/ordering","Refcount/accounting correction"]},
    {name:"Memory-corruption diagnosis", description:"UAF, OOB, invalid/double free, or invalid/wild access title/report", range:typeRange, values:["Use-after-free (read)","Use-after-free (write)","Use-after-free","Out-of-bounds access (read)","Out-of-bounds access (write)","Invalid/double free","Invalid/wild memory access"]},
  ];
  function summedCount(spec, metricRange=null, criterion=null) {
    if (!spec.range) {
      if (!metricRange) return `COUNTA(${nRange})`;
      if (metricRange === dRange && criterion === ">=0") return `COUNT(${dRange})`;
      if (metricRange === dRange && criterion === "<=1") return `COUNTIFS(${dRange},"<>",${dRange},"<=1")`;
      return `COUNTIF(${metricRange},${JSON.stringify(criterion)})`;
    }
    return spec.values.map(value => metricRange
      ? (metricRange === dRange && (criterion === ">=0" || criterion === "<=1")
        ? `COUNTIFS(${spec.range},${JSON.stringify(value)},${metricRange},"<>",${metricRange},${JSON.stringify(criterion)})`
        : `COUNTIFS(${spec.range},${JSON.stringify(value)},${metricRange},${JSON.stringify(criterion)})`)
      : `COUNTIF(${spec.range},${JSON.stringify(value)})`).join("+");
  }
  for (let i = 0; i < groupSpecs.length; i++) {
    const row = 5 + i, spec = groupSpecs[i];
    evaluation.getRange(`A${row}:B${row}`).values = [[spec.name,spec.description]];
    evaluation.getRange(`C${row}`).formulas = [[`=${summedCount(spec)}`]];
    evaluation.getRange(`D${row}`).formulas = [[`=${summedCount(spec,dRange,">=0")}`]];
    evaluation.getRange(`E${row}`).formulas = [[`=${summedCount(spec,dRange,"<=1")}`]];
    evaluation.getRange(`F${row}`).formulas = [[`=IF(D${row}=0,0,E${row}/D${row})`]];
    evaluation.getRange(`G${row}`).formulas = [[`=${summedCount(spec,dRange,">=3")}`]];
    evaluation.getRange(`H${row}`).formulas = [[`=IF(D${row}=0,0,G${row}/D${row})`]];
    evaluation.getRange(`I${row}`).formulas = [[`=${summedCount(spec,sRange,"∞")}`]];
    evaluation.getRange(`J${row}`).formulas = [[`=${summedCount(spec,tempRange,"unbounded")}`]];
  }
  evaluation.getRange("F5:F8").format.numberFormat = "0.0%"; evaluation.getRange("H5:H8").format.numberFormat = "0.0%";

  evaluation.getRange("A10:J10").merge(); evaluation.getRange("A10").values = [["Structural distance versus stack visibility"]]; styleSection(evaluation.getRange("A10:J10"));
  evaluation.getRange("A12:F18").values = [["Grade","Bugs","S=0","Finite S>0","S=∞","Off-stack among known S"], ...[0,1,2,3,4,5].map(d => [`D${d}`,null,null,null,null,null])]; styleHeader(evaluation.getRange("A12:F12"));
  for (let row = 13; row <= 18; row++) {
    const d = row - 13;
    evaluation.getRange(`B${row}`).formulas = [[`=COUNTIF(${dRange},${d})`]];
    evaluation.getRange(`C${row}`).formulas = [[`=COUNTIFS(${dRange},${d},${sRange},"0")`]];
    evaluation.getRange(`E${row}`).formulas = [[`=COUNTIFS(${dRange},${d},${sRange},"∞")`]];
    evaluation.getRange(`D${row}`).formulas = [[`=B${row}-C${row}-E${row}-COUNTIFS(${dRange},${d},${sRange},"unknown")`]];
    evaluation.getRange(`F${row}`).formulas = [[`=IF(B${row}-COUNTIFS(${dRange},${d},${sRange},"unknown")=0,0,E${row}/(B${row}-COUNTIFS(${dRange},${d},${sRange},"unknown")))`]];
  }
  evaluation.getRange("F13:F18").format.numberFormat = "0.0%"; addDistanceFormats(evaluation.getRange("A13:A18"));
  evaluation.getRange("H12:I18").values = [["Grade","Off-stack share"], ...[0,1,2,3,4,5].map(d => [`D${d}`,null])]; styleHeader(evaluation.getRange("H12:I12"));
  for (let row = 13; row <= 18; row++) evaluation.getRange(`I${row}`).formulas = [[`=F${row}`]];
  evaluation.getRange("I13:I18").format.numberFormat = "0.0%";
  const sChart = evaluation.charts.add("bar", evaluation.getRange("H12:I18"));
  sChart.title = "Off-stack prevalence by structural distance"; sChart.hasLegend = false; sChart.setPosition("K4", "R19");
  sChart.xAxis = { axisType: "textAxis" }; sChart.yAxis = { numberFormatCode: "0%" };

  evaluation.getRange("A21:J21").merge(); evaluation.getRange("A21").values = [["Data-completeness comparison"]]; styleSection(evaluation.getRange("A21:J21"));
  evaluation.getRange("A22:D29").values = [
    ["Metric","Earlier dataset","Current dataset","Change"],
    ["Fixed bugs in live listing",baseline.fixed_listing_records ?? null,completeness.live_fixed_listing ?? null,null],
    ["Local bug JSON",baseline.local_bug_json ?? null,completeness.local_bug_json ?? null,null],
    ["Crash reports meeting inclusion rule",baseline.usable_crash_reports ?? null,completeness.nonempty_crash_reports ?? null,null],
    ["Included report-and-patch bugs",baseline.included_report_and_patch_bugs ?? null,completeness.included ?? bugs.length,null],
    ["No hashed fix in metadata",baseline.title_only_fix_bugs_with_report ?? null,completeness.no_hashed_fix ?? null,null],
    ["Hashed fix without local patch",0,completeness.hashed_fix_without_patch ?? null,null],
    ["Exact-title fix hashes recovered",0,supplementalRecovered,null],
  ];
  styleHeader(evaluation.getRange("A22:D22"));
  evaluation.getRange("D23").formulas = [["=C23-B23"]]; evaluation.getRange("D23:D29").fillDown();
  evaluation.getRange("B23:D29").format.numberFormat = "#,##0";

  evaluation.getRange("A30:J30").merge(); evaluation.getRange("A30").values = [["Confidence and patch-structure sensitivity"]]; styleSection(evaluation.getRange("A30:J30"));
  evaluation.getRange("A31:F35").values = [
    ["Slice","Resolved bugs","D3–D5","Far share","Known S","S=∞ share"],
    ["All resolved",null,null,null,null,null],
    ["High CS + non-low D confidence",null,null,null,null,null],
    ["Single-hunk fixes",null,null,null,null,null],
    ["Multi-hunk fixes",null,null,null,null,null],
  ]; styleHeader(evaluation.getRange("A31:F31"));
  evaluation.getRange("B32").formulas = [[`=COUNT(${dRange})`]]; evaluation.getRange("C32").formulas = [[`=COUNTIF(${dRange},">=3")`]]; evaluation.getRange("D32").formulas = [["=C32/B32"]]; evaluation.getRange("E32").formulas = [[`=COUNTA(${sRange})-COUNTIF(${sRange},"unknown")`]]; evaluation.getRange("F32").formulas = [[`=COUNTIF(${sRange},"∞")/E32`]];
  evaluation.getRange("B33").formulas = [[`=COUNTIFS(${csConfRange},"high",${dConfRange},"<>low",${dRange},">=0")`]]; evaluation.getRange("C33").formulas = [[`=COUNTIFS(${csConfRange},"high",${dConfRange},"<>low",${dRange},">=3")`]]; evaluation.getRange("D33").formulas = [["=C33/B33"]]; evaluation.getRange("E33").formulas = [[`=COUNTIFS(${csConfRange},"high",${dConfRange},"<>low",${sRange},"<>unknown")`]]; evaluation.getRange("F33").formulas = [[`=COUNTIFS(${csConfRange},"high",${dConfRange},"<>low",${sRange},"∞")/E33`]];
  evaluation.getRange("B34").formulas = [[`=COUNTIFS(${hunkCountRange},1,${dRange},"<>",${dRange},">=0")`]]; evaluation.getRange("C34").formulas = [[`=COUNTIFS(${hunkCountRange},1,${dRange},">=3")`]]; evaluation.getRange("D34").formulas = [["=C34/B34"]]; evaluation.getRange("E34").formulas = [[`=COUNTIFS(${hunkCountRange},1,${sRange},"<>unknown")`]]; evaluation.getRange("F34").formulas = [[`=COUNTIFS(${hunkCountRange},1,${sRange},"∞")/E34`]];
  evaluation.getRange("B35").formulas = [[`=COUNTIFS(${hunkCountRange},">1",${dRange},"<>",${dRange},">=0")`]]; evaluation.getRange("C35").formulas = [[`=COUNTIFS(${hunkCountRange},">1",${dRange},">=3")`]]; evaluation.getRange("D35").formulas = [["=C35/B35"]]; evaluation.getRange("E35").formulas = [[`=COUNTIFS(${hunkCountRange},">1",${sRange},"<>unknown")`]]; evaluation.getRange("F35").formulas = [[`=COUNTIFS(${hunkCountRange},">1",${sRange},"∞")/E35`]];
  evaluation.getRange("D32:D35").format.numberFormat = "0.0%"; evaluation.getRange("F32:F35").format.numberFormat = "0.0%";
  evaluation.getRange("A37:J40").merge(true); evaluation.getRange("A37:A40").values = [
    ["Interpretation: compare structural and stack axes rather than treating either as a surrogate for the other. The off-stack gradient is an empirical test of the framework's locality prediction."],
    ["Logic/refcount/memory-corruption rows are deterministic operational proxies. They support reproducible comparison but do not replace expert causal adjudication."],
    ["Sensitivity: the strict high-confidence slice is materially less far than the full corpus, while multi-hunk fixes are farther than single-hunk fixes. Report these slices with the headline estimate because extraction confidence, patch breadth, and D(max) affect its magnitude."],
    ["Completeness deltas distinguish live-listing coverage, artifact recovery, and analyzable report+patch inclusion. The prior rule required >80 bytes; the current rule retains every non-empty report as requested."],
  ];
  evaluation.getRange("A37:J40").format = { fill: "#FFF8E7", font: { name: "Aptos", size: 10, color: COLORS.ink }, wrapText: true, verticalAlignment: "center" };
  setWidths(evaluation, [["A",32],["B",62],["C",13],["D",13],["E",13],["F",18],["G",13],["H",18],["I",13],["J",18]], 40);
  evaluation.freezePanes.freezeRows(4);

  const exampleKeys = [
    "extid-0141c834e47059395621", "extid-0315f8fe99120601ba88", "extid-031d0cfd7c362817963f",
    "extid-05d7520be047c9be86e0", "extid-12479ae15958fc3f54ec", "extid-30b53487d00b4f7f0922",
    "extid-005d2a9ecd9fbf525f6a", "extid-0154da2d403396b2bd59", "extid-068ff190354d2f74892f",
    "extid-01218003be74b5e1213a", "extid-038b7bf43423e132b308", "extid-0d33ab192bd50b6c91e6",
    "extid-08936936fe8132f91f1a", "extid-2fa344348a579b779e05", "extid-346474e3bf0b26bd3090",
    "extid-019ced393ab913002b75", "extid-25b83a6f2c702075fcbc", "extid-37fd81fa4305a9eadfb0",
  ];
  const interpretations = {
    "extid-0141c834e47059395621": "RCU guard is added at the IPv6 multicast manifestation statement.",
    "extid-0315f8fe99120601ba88": "The JFS array-index check corrects the exact UBSAN expression site.",
    "extid-031d0cfd7c362817963f": "A lifetime correction touches the crashing unregister statement; alloc/free stacks make Δt unbounded.",
    "extid-05d7520be047c9be86e0": "The bounds repair stays inside the crashing bcachefs formatting function.",
    "extid-12479ae15958fc3f54ec": "Landlock changes the same hook but away from the might_sleep manifestation line.",
    "extid-30b53487d00b4f7f0922": "An OCFS2 consistency guard is earlier in the same lookup function.",
    "extid-005d2a9ecd9fbf525f6a": "The victim assertion and missing reference acquisition are in different functions of bnode.c.",
    "extid-0154da2d403396b2bd59": "Steam input opens a freed object; teardown is corrected in another function of the same driver file.",
    "extid-068ff190354d2f74892f": "io_recv consumes uninitialized state prepared by another function in io_uring/net.c.",
    "extid-01218003be74b5e1213a": "exFAT consumption is in dir.c while initialization is repaired in namei.c.",
    "extid-038b7bf43423e132b308": "An ext4 invariant fires in extent-status code; invalid inode flags are rejected in inode.c.",
    "extid-0d33ab192bd50b6c91e6": "The media test driver frees SI state in another source file of the same component.",
    "extid-08936936fe8132f91f1a": "An XDP warning occurs through a net header while the missing ops lock is added in net/core.",
    "extid-2fa344348a579b779e05": "skb_clone is the net-core victim; HSR fixes the NULL-producing path in another net component.",
    "extid-346474e3bf0b26bd3090": "Generic socket copyout exposes uninitialized address bytes produced in IEEE 802.15.4 code.",
    "extid-019ced393ab913002b75": "I2C object-debugging is the victim; the media frontend repairs its remove lifetime.",
    "extid-25b83a6f2c702075fcbc": "iov_iter detects the overrun, while netfs write-retry resets the iterator incorrectly.",
    "extid-37fd81fa4305a9eadfb0": "vsprintf writes through freed data; media request allocation/lifetime is the cross-subsystem cause.",
  };
  const chosenExamples = exampleKeys.map(k => bugs.find(b => b.bug_key === k)).filter(Boolean);
  const chosenExampleKeys = new Set(chosenExamples.map(b => b.bug_key));
  for (const detector of ["KASAN","KMSAN","UBSAN","KCSAN","Lockdep","WARN","BUG/Oops","RCU diagnostics","Hung-task detector","Leak detector","Kernel fault/other"]) {
    const candidate = bugs.find(b => b.detector === detector && b.cs_confidence === "high" && b.distance != null && !chosenExampleKeys.has(b.bug_key));
    if (candidate) { chosenExamples.push(candidate); chosenExampleKeys.add(candidate.bug_key); }
  }
  const exampleRows = chosenExamples.map(b => [
    b.distance_label, b.title, b.bug_type, b.cs_location, b.farthest_fs_location, b.stack_distance,
    b.temporal_distance, b.patch_titles,
    interpretations[b.bug_key] || `${b.detector} example selected with ${b.cs_strategy}; ${b.full_annotation}.`,
    b.bug_url,
  ]);
  const exampleSheet = workbook.worksheets.add("Examples"); baseSheet(exampleSheet);
  setTitle(exampleSheet, exampleSheet.getRange("A1:J1"), "Representative Crash–Fix Patterns");
  exampleSheet.getRange("A2:J2").merge(); exampleSheet.getRange("A2").values = [[`${exampleRows.length} examples span D0–D5 and detector-specific CS rules. They are illustrations, not a separate sample.`]]; exampleSheet.getRange("A2:J2").format = { fill: COLORS.pale, font: { name: "Aptos", size: 10, color: COLORS.muted } };
  const exHeaders = ["Distance", "Syzbot title", "Bug type", "Crash site", "Farthest fix site", "S", "Δt", "Patch title", "Pattern interpretation", "Syzbot URL"];
  exampleSheet.getRange(`A4:J${exampleRows.length + 4}`).values = [exHeaders, ...exampleRows]; styleHeader(exampleSheet.getRange("A4:J4"));
  exampleSheet.getRange(`A5:J${exampleRows.length + 4}`).format = { font: { name: "Aptos", size: 9, color: COLORS.ink }, wrapText: true, verticalAlignment: "top" };
  addDistanceFormats(exampleSheet.getRange(`A5:A${exampleRows.length + 4}`));
  const exTable = exampleSheet.tables.add(`A4:J${exampleRows.length + 4}`, true, "ExamplesTable"); exTable.style = "TableStyleMedium2";
  exampleSheet.freezePanes.freezeRows(4);
  setWidths(exampleSheet, [["A",22],["B",48],["C",28],["D",46],["E",58],["F",9],["G",32],["H",56],["I",70],["J",48]], exampleRows.length + 4);

  const taxonomy = workbook.worksheets.add("Taxonomy"); baseSheet(taxonomy);
  setTitle(taxonomy, taxonomy.getRange("A1:F1"), "Classification Taxonomy and Rules");
  taxonomy.getRange("A3:C3").values = [["Bug type", "Family", "Operational definition"]]; styleHeader(taxonomy.getRange("A3:C3"));
  const bugDefs = [
    ["Use-after-free", "Memory safety", "Access after a free; read/write retained from title/report."], ["Out-of-bounds access", "Memory safety", "Slab/heap/global/array access outside the valid object/array."],
    ["NULL dereference", "Memory safety", "NULL or near-NULL access."], ["Uninitialized use", "Memory safety", "KMSAN or report identifies consumption of uninitialized data."],
    ["Invalid/wild memory access", "Memory safety", "KASAN wild/invalid access or bad usercopy without a more specific subtype."], ["Invalid/double free", "Memory safety", "Object is freed twice or through an invalid free path."],
    ["Stack overflow", "Memory safety", "Stack guard/overflow failure."], ["Kernel information leak", "Memory disclosure", "Uninitialized kernel bytes become observable to userspace/network."],
    ["Data race", "Concurrency", "KCSAN reports conflicting unsynchronized accesses."], ["Deadlock/lock ordering", "Concurrency", "Circular dependency or explicit deadlock."],
    ["Lock/context misuse", "Concurrency", "Sleeping/atomic misuse, non-static lock key, or invalid context."], ["Refcount error", "Resource/lifetime", "Reference/accounting invariant failure."],
    ["Hang/stall/lockup", "Liveness", "Hung task, RCU stall, or soft/hard lockup."], ["Arithmetic/type UB", "Undefined behavior", "Shift, integer overflow, division, or UBSAN array-index failure."],
    ["Page fault/general protection fault", "Kernel fault", "Oops/GPF/page fault without a more specific sanitizer diagnosis."], ["Kernel warning", "Invariant violation", "WARN-style manifestation without a stronger normalized type."],
    ["Kernel BUG/assertion", "Invariant violation", "BUG/panic/assertion manifestation without a stronger normalized type."],
  ];
  taxonomy.getRange(`A4:C${bugDefs.length + 3}`).values = bugDefs;
  taxonomy.getRange("E3:F3").values = [["Patch type", "Operational definition"]]; styleHeader(taxonomy.getRange("E3:F3"));
  const patchDefs = [
    ["Validation/guard", "Add/strengthen input, state, NULL, or precondition validation."], ["Synchronization/ordering", "Change locks, RCU, barriers, work/timer cancellation, or execution ordering."],
    ["Lifetime/resource management", "Change allocation, free, teardown, release, or object lifetime."], ["Logic/control-flow correction", "Correct conditions, branches, state transitions, or fallback logic."],
    ["Initialization/state correction", "Initialize/reset/update state or flags consistently."], ["Bounds/size correction", "Correct a limit, length, size, count, or index."],
    ["API/protocol contract", "Use an API, ioctl, attribute, or protocol according to its contract."], ["Arithmetic/type correction", "Correct a type, cast, shift, signedness, or arithmetic."],
    ["Error-path handling", "Repair error propagation, unwind, rollback, or failure cleanup."], ["Refcount/accounting correction", "Correct reference or resource accounting operations."],
  ];
  taxonomy.getRange(`E4:F${patchDefs.length + 3}`).values = patchDefs;
  taxonomy.getRange("A23:F23").merge(); taxonomy.getRange("A23").values = [["Structural grading hierarchy"]]; styleSection(taxonomy.getRange("A23:F23"));
  taxonomy.getRange("A24:C29").values = [
    ["D0 Coincident", "Exact/adjacent changed statement", "Changed old line or insertion anchor within ±2 lines of CS."],
    ["D1 Intra-function", "Same function", "FS function equals CS function, different line."],
    ["D2 Intra-file", "Same source file", "Different/unknown function in the same file."],
    ["D3 Intra-component", "Same component", "Different files in the path-derived component/driver."],
    ["D4 Intra-subsystem", "Same subsystem", "Different components in the path-derived subsystem family."],
    ["D5 Cross-subsystem", "Different subsystems", "Path-derived subsystem families differ; historical MAINTAINERS validation required."],
  ];
  styleHeader(taxonomy.getRange("A24:A29"));
  taxonomy.getRange("A4:F29").format.wrapText = true; taxonomy.getRange("A4:F29").format.verticalAlignment = "top";
  setWidths(taxonomy, [["A",31],["B",24],["C",70],["D",5],["E",34],["F",72]], 29);
  taxonomy.freezePanes.freezeRows(3);

  const manual = bugs.filter(b => b.review_status !== "Automated classification");
  const qc = workbook.worksheets.add("QC"); baseSheet(qc);
  setTitle(qc, qc.getRange("A1:I1"), "Quality Control and Manual-Review Queue");
  qc.getRange("A3:D7").values = [["Metric","Value","Share","Meaning"],["CS high confidence",null,null,"Explicit source or title function matched to symbolized stack"],["CS medium confidence",null,null,"Ordinary title match or labeled KCSAN access stack"],["Manual review queue",manual.length,null,"Unresolved CS/distance or missing FS function"],["Structurally unresolved",null,null,"No symbolized CS path in the downloaded report"]]; styleHeader(qc.getRange("A3:D3"));
  qc.getRange("B4").formulas = [[`=COUNTIF('Bugs'!$${bugCol("CS confidence")}$2:$${bugCol("CS confidence")}$${bugLastRow},"high")`]];
  qc.getRange("B5").formulas = [[`=COUNTIF('Bugs'!$${bugCol("CS confidence")}$2:$${bugCol("CS confidence")}$${bugLastRow},"medium")`]];
  qc.getRange("B7").formulas = [[`=COUNTIF(${dlRange},"Unresolved")`]];
  for (const row of [4,5,6,7]) qc.getRange(`C${row}`).formulas = [[`=B${row}/COUNTA(${nRange})`]];
  qc.getRange("C4:C7").format.numberFormat = "0.0%";
  qc.getRange("A9:I9").values = [["Bug key","Title","CS","Fix path(s)","Fix function(s)","Distance","CS confidence","QC flags","Syzbot URL"]]; styleHeader(qc.getRange("A9:I9"));
  const qcRows = manual.map(b => [b.bug_key,b.title,b.cs_location,b.fix_paths,b.fix_functions,b.distance_label,b.cs_confidence,b.qc_flags,b.bug_url]);
  if (qcRows.length) qc.getRange(`A10:I${qcRows.length + 9}`).values = qcRows;
  qc.getRange(`A10:I${qcRows.length + 9}`).format = { font: { name: "Aptos", size: 9, color: COLORS.ink }, wrapText: true, verticalAlignment: "top" };
  addDistanceFormats(qc.getRange(`F10:F${qcRows.length + 9}`));
  const qcTable = qc.tables.add(`A9:I${qcRows.length + 9}`, true, "QCTable"); qcTable.style = "TableStyleMedium3";
  qc.freezePanes.freezeRows(9); setWidths(qc, [["A",25],["B",50],["C",48],["D",58],["E",40],["F",22],["G",15],["H",70],["I",48]], qcRows.length + 9);

  const manifestHeaders = ["Bug key", "Title", "Report present", "Hashed fixes", "Patches available", "Included", "Exclusion reason"];
  const manifestRows = manifest.map(m => [m.bug_key,m.title,m.report,m.fix_commits_with_hash,m.patches_available,m.included,m.exclusion_reason]);
  const manifestSheet = workbook.worksheets.add("Cohort Manifest"); baseSheet(manifestSheet);
  const manifestLastRow = manifestRows.length + 1;
  manifestSheet.getRange(`A1:G${manifestLastRow}`).values = [manifestHeaders, ...manifestRows]; styleHeader(manifestSheet.getRange("A1:G1"));
  manifestSheet.getRange(`A2:G${manifestLastRow}`).format.font = { name: "Aptos", size: 9, color: COLORS.ink };
  manifestSheet.getRange(`F2:F${manifestLastRow}`).conditionalFormats.add("cellIs", { operator: "equal", formula: "TRUE", format: { fill: COLORS.d0, font: { bold: true, color: COLORS.green } } });
  const manifestTable = manifestSheet.tables.add(`A1:G${manifestLastRow}`, true, "CohortManifestTable"); manifestTable.style = "TableStyleMedium2";
  manifestSheet.freezePanes.freezeRows(1); manifestSheet.freezePanes.freezeColumns(2);
  setWidths(manifestSheet, [["A",25],["B",52],["C",15],["D",14],["E",16],["F",12],["G",58]], manifestLastRow);

  // Move dashboard to the front is not supported by the quick facade; README is
  // intentionally first, and Dashboard remains near the front of the logical map.

  await fs.mkdir(await writablePath(path.dirname(outputPath)), { recursive: true });
  await fs.mkdir(await writablePath(previewDir), { recursive: true });

  const keyChecks = [];
  for (const [sheetName, range] of [["Dashboard","A1:M52"],["Evaluation","A1:R40"],["Definitions","A1:H35"],["Bugs",`A1:M8`],["Fix Hunks","A1:X8"],["Evidence","A1:L8"],["Examples",`A1:J${Math.min(exampleRows.length + 4, 36)}`],["Taxonomy","A1:F29"],["QC",`A1:I${Math.min(qcRows.length + 9, 30)}`],["Cohort Manifest","A1:G12"],["README","A1:H36"]]) {
    const inspected = await workbook.inspect({ kind: "table", range: `${sheetName}!${range}`, include: "values,formulas", tableMaxRows: 12, tableMaxCols: 14, maxChars: 3500 });
    keyChecks.push({ sheetName, chars: inspected.ndjson.length });
    const preview = await workbook.render({ sheetName, range, scale: 1, format: "png" });
    await fs.writeFile(await writablePath(path.join(previewDir, `${sheetName.replaceAll(" ", "_")}.png`)), new Uint8Array(await preview.arrayBuffer()));
  }
  const errors = await workbook.inspect({ kind: "match", searchTerm: "#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A", options: { useRegex: true, maxResults: 300 }, summary: "final formula error scan", maxChars: 4000 });
  const output = await SpreadsheetFile.exportXlsx(workbook);
  await output.save(await writablePath(outputPath));
  console.log(JSON.stringify({ outputPath, sheets: 11, bugs: bugs.length, hunks: hunks.length, previews: previewDir, formulaErrorScan: errors.ndjson, checks: keyChecks }, null, 2));
}

await buildWorkbook();
