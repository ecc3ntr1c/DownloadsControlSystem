# Report builder handoff

Parent has run the artifact marker successfully exactly once. Do not run it again.
Internal drafts are authorized; final delivery requires complete evidence for all four labs.

Bundled Python:
`/Users/alexandr/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3`

Bundled LibreOffice wrapper (never use the desktop installation):
`/Users/alexandr/.cache/codex-runtimes/codex-primary-runtime/dependencies/bin/override/soffice`

The retained DOCX supplies title paragraphs, page geometry, styles, footer, and
all 40 answers. Its obsolete body is rebuilt. Only address/configuration data
are taken from JSON; model results and all four model PNGs are not copied.
Original report is retained untouched.

Run from lab_work (absolute paths also supported):

```sh
PYTHON_BIN=/Users/alexandr/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3
"$PYTHON_BIN" build_report.py --manifest report_manifest.json --strict
```

The active report_manifest.json contains partial verified evidence. Do not overwrite it.
The template is only an empty schema reference.
All outcome claims are supplied in that manifest, not inferred by the builder.

For each lab, screenshots is an ordered array of objects:

```json
{
  "file": "01_topology.png",
  "slot": "topology",
  "caption": "Топология сети из двух подсетей",
  "note": "Optional verified explanation after the screenshot",
  "before": "Optional paragraph before the screenshot",
  "width_cm": 17.1,
  "max_height_cm": 11.4,
  "page_break_before": false
}
```

Only file and caption are required. Missing slot defaults to checks. Caption
numbering is generated. Screenshots preserve aspect ratio. Report copies may be rectangular crops of raw
captures; originals are retained and crop coordinates are logged in report_crop_log.json.

Slots:

| Lab | Available slots in document order |
| --- | --- |
| 1 | topology, configuration, checks |
| 2 | topology, access, trunk, isolation, routing, checks |
| 3 | topology, stp_initial, stp_root, lacp, failure, storm, checks |
| 4 | topology, interfaces, dhcp, static, rip, checks |

`slot_observations` maps a slot name to a list of paragraphs inserted before
its screenshots. `observations` is a list of paragraphs for the final analysis.
`conclusion` is a string; the builder prefixes it with «Вывод. ».

Optional single results table:

```json
"results": {
  "headers": ["Проверка", "Результат"],
  "rows": [["PC1 → PC3", "Successful"]],
  "widths": [10, 6]
}
```

Optional `tables` list has the same schema plus optional `title`, for e.g.
actual STP roles and DHCP leases. Tables are added in analysis order.

`--strict` requires `complete: true` for every lab after evidence review. It verifies
required screenshot stages and conclusion for each lab, evidence text or result table,
valid slots, all images inserted, and absence of stale model text.
It does not assert screenshot truth; parent must inspect actual captures.

Default final path: `lab_work/final/Setevye_Tehnologii_Gorokhov.docx`.
Render with documents skill render_docx.py and inspect ALL pages before delivery.

Potential rendering adjustments: figure max_height_cm defaults to 11.4, allowing
two landscape screenshots on many pages. Taller terminal captures may need 14–18
cm to keep text readable. Set explicit page_break_before for a full-page image.
There is no manually paginated TOC to become stale; Word headings provide navigation.

An internal partial draft has been authored and rendered. render3 contains 22 pages;
all were visually inspected. The builder has since gained an explicit subnet boundary
table, a stricter completeness gate, and a correction distinguishing RIP metric from AD.
Rerender after new evidence is inserted. Final layout must be inspected in full again.
