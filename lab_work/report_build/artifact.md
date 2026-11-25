# Laboratory report artifact contract

Authority: the retained source report at
`../Setevye_Tehnologii_Codex/report/Setevye_Tehnologii_Lab_01-04_Gorokhov.docx`.
The user's final requested scope is one completed report covering all four labs.
The source method sheets determine technical requirements; the former report's
model results and images are not evidence and must not be copied.

## Retained design

- A4 portrait; top 1.7004 cm, bottom 1.59985 cm, left 2.00025 cm, right 1.59985 cm.
- Preserve the eight title-page paragraphs and institutional/student/reviewer details.
- Times New Roman, black; body 12 pt, Heading 1 16 pt, Heading 2 13 pt.
- Caption 10 pt; table 10.5 pt; CLI examples Courier New 9.5 pt.
- No page number on title; centered numeric footer thereafter.
- Each lab begins on a new page. Forty control questions remain in lab order.

## Intentional departures

- Replace old manual page table of contents with a concise scope page and heading navigation.
- Rebuild the body with real native Packet Tracer evidence and independently checked address data.
- Use readable rectangular screenshot crops; preserve raw screenshots and log crop coordinates.
- Keep figures, captions and short explanatory notes together. Keep short tables intact.
- Correct the routing answer in lab 1 question 8 to cover source-routing forms and route learning.
- Show N = 4 for labs 1–3 and explicit variant 4 for lab 4.

## Completion gate

- Artifact authoring marker was successfully run exactly once by parent; never repeat it.
- Every lab must have `complete: true` in the evidence manifest after review.
- Required experiment stages must have screenshots, and outcomes must come from real evidence.
- Final `--strict` build must pass, then all rendered page PNGs must be visually inspected.
- Use only the bundled Python and bundled headless LibreOffice, never the desktop installation.
- Deliver one DOCX under `lab_work/final`; draft DOCX, PDF and render PNGs remain internal.

## Current QA state

The partial render3 draft was inspected on every one of its 22 pages. No text or
image clipping, overlap, missing glyphs, detached captions or split table rows
were found. Render6 contains 38 pages and 52 figures: labs 1/2 are complete,
lab 3 awaits the STP-disabled ARP experiment, and lab 4 awaits the two final static
ping images. Newly added dense CLI pages 11, 13, 16, 21, 23, 25, 26 and 27 were
visually inspected; captions and complete output fit, without clipping or overlap.
This does not substitute for a full final render-and-inspect pass.

The target of approximately 25–35 pages is subordinate to readable evidence for
all required stages and all 40 questions; the final is expected to be longer.
One question occupies the final draft page; rebalance after final insertions.
