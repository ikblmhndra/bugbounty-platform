# Scanning Pipeline

The primary orchestration entrypoint is:

- `app/workers/scan_tasks.py` -> `run_scan(scan_id)`

The task is enqueued from:

- `app/api/scans.py` -> `run_scan.apply_async(args=[scan.id], queue="scans")`

## Pipeline Stages

1. **Subdomain enumeration**
   - Tools: `subfinder`, `assetfinder`
   - Output: subdomain assets

2. **Host probing**
   - Tool: `httpx`
   - Output: alive URLs, response metadata (status, tech, headers)

3. **URL collection**
   - Tools: `gau`, `waybackurls`, `katana`
   - Output: expanded URL asset inventory

4. **Screenshot capture** (optional)
   - Tool: `gowitness`
   - Controlled by `run_gowitness`

5. **Endpoint fuzzing** (optional)
   - Tool: `ffuf`
   - Controlled by `run_ffuf`

6. **Vulnerability scanning**
   - Tool: `nuclei`
   - Controlled by `nuclei_severity`

7. **Normalization**
   - Converts raw nuclei output into normalized `Finding` records

8. **Attack path analysis**
   - Correlates findings into analyst-readable attack paths

## Inputs and Options

Scan creation payload includes:

- `domain`
- `options.run_ffuf` (bool)
- `options.run_gowitness` (bool)
- `options.nuclei_severity` (string CSV)
- `options.ffuf_wordlist` (path)

## Persistence Behavior

At each stage, the worker writes:

- scan progress (`steps_total`, `steps_completed`, `current_step`)
- execution logs (`Log`)
- discovered assets/findings/attack paths

This supports partial progress visibility even when one stage fails.

## Failure Model

- Stage failures are logged and often downgraded to warnings
- Pipeline continues when safe fallback values exist
- Fatal task failures mark scan status as `FAILED`

## Cancellation

`DELETE /api/v1/scans/{scan_id}` revokes the Celery task if a task id exists and sets scan status to `CANCELLED`.
