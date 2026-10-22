# Reporting

AsterScan can write an offline HTML report while keeping its usual console output:

```sh
python asterscan.py -p /path/to/inspect --report scan-report.html --noindicator
```

The report is self-contained and makes no network requests. Use its Findings view to filter and inspect matches, Activity to review errors and scan messages, and Rule sources to see recorded signature revisions. It includes a JSON download for further analysis. AsterScan will not overwrite an existing report path. Choose a new filename for each scan.

For automation, `--jsonl` writes UTF-8 JSON Lines to standard output and suppresses the progress indicator. Usually pair it with `--nolog`; `--jsonl` and `--csv` are mutually exclusive.

```sh
python asterscan.py -p /path/to/inspect --jsonl --nolog > scan.jsonl
```

Each line has `time` (UTC ISO 8601), `level`, `module`, and `message`. File findings additionally have `data` with `kind: "file"`, `path`, `score`, `file_type`, `size`, `hashes`, and `reasons`. A final coverage event gives paths processed, files seen, and file contents inspected. Other Windows checks can produce alert or warning events without structured file data. Consumers should ignore fields they do not recognize; the HTML report embeds schema version `1`.

The HTML view keeps every alert, warning, error, result, and file finding. It keeps up to 2,000 routine notices and states how many additional routine notices were omitted. Its activity panel displays the first 500 captured events; Download JSON retains the complete captured set. The report is not a claim of malware absence or detection accuracy. A `SCAN INCOMPLETE` status takes precedence over a clean or detected status when coverage errors occur. If initialization stops or a scan is interrupted, no HTML report is produced; interruption exits with status `130`.

**Privacy:** Reports can contain usernames, local paths, hostnames, hashes, and rule descriptions. They stay on the device unless you share them. Inspect before uploading or attaching one elsewhere.
