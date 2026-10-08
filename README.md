# CTI Casefile 001 — Find the Persistence

A single-page, browser-based **cyber threat intelligence investigation simulator**.

You are a Tier 1 escalation analyst. Three alerts fired on one workstation and nobody
has told you which of them matter. You get the raw event stream, three alerts, an
account record and a baseline of the rest of the estate. You have to work out what
actually happened, prove it, name it, and write an assessment someone else can act on.

One case, six stages, 100 XP, about 25 minutes.

**No account. No setup. No terminal. No Wireshark, no VM, no SIEM licence.**

---


## Play it online

The case is deployed as a GitHub Page and runs entirely in the browser:

### &nbsp; [https://CE47.github.io/CTIA_Lab001/](https://CE47.github.io/CTIA_Lab001/)

Open the link in any current browser and press **BEGIN INVESTIGATION**. No account,
no installation, no build step — progress is saved locally to the browser only.

---

## How the case works

| Stage | Name | What you do | XP |
|---|---|---|---|
| — | Briefing | Read the mission, press BEGIN | — |
| 01 | **Detect** | Open all five evidence items | 10 |
| 02 | **Collect** | Tag 28 log lines SIGNAL / CONTEXT / NOISE | 10 |
| 03 | **Correlate** | Order the timeline, name the pattern | 10 |
| 04 | **Connect** | Draw six threads on the pinboard | 10 |
| 05 | **Analyze** | Behaviour, decode the payload, ATT&CK, classify IoCs | 32 |
| 06 | **Report** | Scope, findings, justification, confidence, response | 18 |

Then a debrief sheet: rank, XP ledger, preserved indicators, and your analyst journal.

The pedagogical spine is **progressive disclosure**. The word "persistence", the
ATT&CK ID, and the vocabulary of indicators are all withheld until you have already
found the artifacts yourself. Feedback panels explain *why*, never just mark you
wrong.

**Analyst Assist** offers three levels of help and never blocks you — it multiplies
the *next* XP award by 0.85 / 0.7 / 0.5, so the final rank still reflects what you
found unaided. Nothing is taken away for experimenting; re-tagging is free, and any
section you answer imperfectly can be re-answered with **TRY AGAIN** as often as you
like. A retry only ever pays the improvement, so it cannot be farmed.

**The only thing that ever gates you is leaving a section unanswered.** A wrong answer
lowers your score and your rank; it never blocks progress, and there is no state from
which the case cannot be completed.

Progress is saved to `localStorage` under `cti-casefile-001-v2`. Reload and the
briefing offers `RESUME INVESTIGATION — N XP`. `RESET CASEFILE` clears it.

---

## Accessibility notes

- The whole game is playable with the keyboard alone. Tab to a board card and press
  Enter or Space to arm it, Tab to the second card and press Enter to choose a
  relation, then Enter on the verb. Escape cancels a pending thread.
- Focus is trapped inside the evidence modal and the debrief sheet, and returns to
  the element that opened them.
- `prefers-reduced-motion` is respected.
- There is a `@media print` block — the debrief sheet prints as a clean intelligence
  product.

## Browser support

Any current evergreen browser. Uses `localStorage`, Pointer Events, CSS custom
properties and `Element.closest`. Degrades to "plays without saving" if
`localStorage` is unavailable (private mode).
