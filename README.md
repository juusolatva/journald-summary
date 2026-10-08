# journald-summary

Condenses systemd journal logs from a handful of Linux servers into short daily reports per host, by filtering and deduplicating them into patterns. A later stage will send the reports to a local LLM for analysis.

The goal is to spot software and hardware problems (failed units, crashes, disk, memory, filesystem, thermal and power issues, misconfiguration). Security monitoring (intrusion detection, auditing, login attempts, scanning) is out of scope; dedicated tools such as auditd cover it.
