# Journal problem analysis

Journal evidence and its interpretation help identify software and hardware problems on Linux hosts.

## Language

### Journal evidence

**Host**:
A Linux machine whose journal entries are considered together, whether its journal is local or received remotely.

**Journal entry**:
One journal record containing a message and context such as its origin, time and priority; a message can span multiple lines.
_Avoid_: Log line

**Source**:
The normalized origin attributed to an entry within a host, such as the kernel, a systemd unit or a program identifier.

**Journal priority**:
The urgency attached to a journal entry, ranging from emergency to debug; a pattern carries the most urgent priority among its entries.
_Avoid_: Issue severity

### Selection and patterns

**Rule**:
A named selection criterion for a recognized software or hardware problem type, with precedence over noise exclusions and priority limits.

**Noise**:
Journal entries matched by a configured exclusion criterion when no rule matches, regardless of their journal priority.
_Avoid_: Harmless entries

**Priority exception**:
A selection criterion for entries, such as boot messages, that are relevant even at low journal priority, subject to noise exclusions.

**Selected entry**:
A journal entry retained for inclusion in a report through a rule match, its journal priority or a priority exception, after applicable noise exclusions.

**Template**:
The normalized message text shared by a pattern's entries, with variable details replaced or removed.
_Avoid_: Pattern (when referring only to the message text)

**Pattern**:
A group of selected entries in one host's report that share the same source and template, together with their count, time range and example message.
_Avoid_: Issue, template

**New pattern**:
A pattern absent from the host's saved pattern history at the start of a run, regardless of how old the underlying event or problem is.
_Avoid_: New issue, unknown issue

### Reports and analysis

**Report**:
A condensed account of the entries read for one host in one run, including selection counts and the selected patterns.
_Avoid_: Analysis

**Report with no selected patterns**:
A report containing no retained journal evidence; when entries were read, it records that none met the selection criteria.
_Avoid_: Empty report (without specifying whether entries were read)

**Report with no journal entries**:
A report for a host from which no entries were read, representing missing journal evidence and a possible host or log delivery problem.

**Chunk**:
A portion of one report considered in an individual analysis, containing whole patterns and the report's shared context.

**Analysis**:
An interpretation of one report, consisting of an overall summary and any issues identified; interpretations of separate chunks contribute to one final analysis.
_Avoid_: Report

**Issue**:
A software, hardware or journal availability problem identified in an analysis, potentially supported by several related patterns.
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
A saved report with a recorded analysis outcome, including either an analysis or an explicit failure analysis, so it is no longer pending.

**Failure analysis**:
A recorded outcome stating that a report could not be analyzed after reaching the age limit for repeated report or reply failures.
