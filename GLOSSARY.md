# Glossary: Journal problem analysis

Journal evidence and its interpretation help identify software and hardware problems on Linux hosts.

## Language

### Journal evidence

**Host**:
A Linux machine whose journal entries are considered together, whether its journal is local or received remotely.

**Journal entry**:
One journal record containing a message and context such as its origin, time and priority; a message can span multiple lines.
_Avoid_: Log line

**Journal cursor**:
The opaque position token recorded for a host to resume reading journal entries on subsequent runs without gaps or duplicates.
_Avoid_: Timestamp checkpoint

**Source**:
The normalized origin attributed to an entry within a host, such as the kernel, a systemd unit or a program identifier.

**Journal priority**:
The urgency attached to a journal entry, ranging from emergency to debug; an entry without a valid priority counts as info. A pattern carries the most urgent priority among its entries.
_Avoid_: Issue severity

### Selection and patterns

**Priority limit**:
The least urgent journal priority that is selected without a rule match or priority exception, currently warning (configured as `MAX_PRIORITY`).
_Avoid_: Severity threshold

**Rule**:
A named selection criterion for a recognized software or hardware problem type, with precedence over noise exclusions and the priority limit (configured as `RULES`).

**Noise exclusion**:
A configured criterion for routine entries that drops them when no rule matches, regardless of their journal priority or any priority exception (configured as `NOISE`).

**Noise**:
Journal entries dropped by a noise exclusion.
_Avoid_: Harmless entries

**Priority exception**:
A selection criterion for entries, such as boot messages, that are relevant even when less urgent than the priority limit, subject to noise exclusions (configured as `ALWAYS_INCLUDE`).
_Avoid_: Always include (as an absolute guarantee, since noise exclusions take precedence)

**Selected entry**:
A journal entry kept for inclusion in a report through a rule match, or, when no noise exclusion drops it, through a journal priority at least as urgent as the priority limit or a priority exception.

**Template**:
The normalized message text shared by a pattern's entries, with variable details replaced or removed. The report labels it `pattern:`.
_Avoid_: Pattern (when referring only to the message text)

**Pattern**:
A group of selected entries from one run for one host that share the same source and template, together with their count, time range, most urgent journal priority, rule matches and example message. The same source and template in a later run is the same pattern, recognized by its pattern key.
_Avoid_: Issue, template

**Pattern key**:
A short identifier derived from a pattern's source and template that recognizes the same pattern across runs; changes to normalization or source attribution can give an existing pattern a new key.

**Saved pattern history**:
The pattern keys recorded by a host's normal-mode runs, each with the time it was first seen (stored in `seen.json`).

**New pattern**:
A pattern whose key is absent from the host's saved pattern history at the start of a run, regardless of how old the underlying event or problem is.
_Avoid_: New issue, unknown issue

### Reports and analysis

**Normal mode**:
A run without a time window, as started by the daily timer, that continues from the host's saved cursor (or, when there is none, reads an initial window configured as `INITIAL_SINCE`). Only after producing its report does it save the advanced cursor and add any new patterns to the saved pattern history. Each of the two is saved atomically on its own, not together, so an interrupted save can record the new patterns without advancing the cursor.

**Preview mode**:
A run for a specified time window that inspects journal entries and marks new patterns against the saved pattern history, without reading or advancing the host's saved cursor, writing state or saving the report, so its report is never analyzed.
_Avoid_: Test run

**Report**:
A condensed account of the entries read for one host in one run, including selection counts and the selected patterns.
_Avoid_: Analysis

**Report with no selected patterns**:
A report in which no entries were selected, although it may have read entries, including entries dropped as noise. When no entries were read at all, it is also a report with no journal entries, which analysis treats differently.
_Avoid_: Empty report (without specifying whether entries were read)

**Report with no journal entries**:
A report for a host from which no entries were read, representing missing journal evidence and a possible host or log delivery problem; its analysis records this as a high-severity issue rather than finding no issues.

**Chunk**:
A portion of one report sent in an individual analysis request, containing whole patterns and the report's header as shared context; a small report is a single chunk.

**Chunk analysis**:
The interpretation of one chunk of a multi-chunk report, with a summary and issues like an analysis, used only as input to the merge request.
_Avoid_: Analysis (for the result of one chunk)

**Merge request**:
A secondary analysis request that combines the chunk analyses of a multi-chunk report, together with its header, into one final analysis for the report.
_Avoid_: Final chunk

**Analysis**:
An interpretation of one report, consisting of an overall summary and any issues identified; for a multi-chunk report, it is produced by merging the chunk analyses.
_Avoid_: Report

**Issue**:
A problem identified in an analysis, such as a software or hardware problem, missing journal evidence or a report that could not be analyzed, potentially supported by several related patterns.
_Avoid_: Pattern, rule match

**Issue severity**:
The assessed impact of an issue: critical for ongoing or imminent data loss or outage, high for a failing service or component, medium for misconfiguration or degraded operation, and low for minor warnings worth attention.
_Avoid_: Journal priority

**Known issue**:
An issue matching an operator's supplied description of an existing problem, still relevant to the analysis even when already acknowledged.
_Avoid_: Previously seen pattern

**Pending report**:
A saved report without a recorded analysis outcome, still awaiting analysis or a later attempt.

**Analyzed report**:
A saved report with a recorded analysis outcome, either an analysis or a failure analysis, so it is no longer pending.

**Failure analysis**:
A recorded outcome stating that a report could not be analyzed, written when reading the report fails or a request gets no valid reply after all its attempts, once the report has reached the age limit (configured as `GIVE_UP_DAYS`). An unreachable analysis server never produces one; the report stays pending.
