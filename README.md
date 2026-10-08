             PATCH AUTOMATION PLATFORM

                    InsightVM
                       │
                       ▼
                Vulnerability Run
                       │
                       ▼
                 Classification
                       │
                       ▼
              Remediation Jobs
                       │
              ┌────────┴────────┐
              ▼                 ▼
          Review             Approval
              │                 │
              └────────┬────────┘
                       ▼
                  GitLab
                       │
                       ▼
                 Ansible Tower

                       │
                       ▼
                 Actual Patch


                
                        CORPORATE USERS
                               │
                               │
                         SAML / AD SSO
                               │
                               ▼
                    ┌─────────────────────┐
                    │     Next.js         │
                    │     Frontend        │
                    │                     │
                    │ Dashboard            │
                    │ Reports              │
                    │ Run Automation       │
                    │ Results              │
                    │ Generated Files      │
                    │ Settings             │
                    └──────────┬──────────┘
                               │
                               │ HTTPS / REST
                               ▼
                    ┌─────────────────────┐
                    │    Backend API      │
                    │   Node + Express    │
                    │                     │
                    │ Auth / SSO           │
                    │ Run API              │
                    │ Report API           │
                    │ Config API           │
                    │ GitLab API           │
                    │ Worker orchestration │
                    └──────────┬──────────┘
                               │
                               │ start job
                               ▼
                    ┌─────────────────────┐
                    │    Python Worker    │
                    │                     │
                    │ patch-auto.py       │
                    │                     │
                    │ InsightVM           │
                    │ CSV parsing         │
                    │ Classification      │
                    │ JSON generation     │
                    │ INI generation      │
                    │ GitLab publishing   │
                    │ Email               │
                    └──────┬────────┬─────┘
                           │        │
                    ┌──────┘        └────────┐
                    ▼                         ▼
              InsightVM                    GitLab
              API                           Repository
                                              │
                                              ▼
                                      Ansible Tower

## Synthetic InsightVM data

The repository includes a local InsightVM API emulator and CSV fixtures so the
worker can be tested without access to a Rapid7 console or production findings.
The fixtures contain report IDs `52` (BI) and `59` (DE), matching the active
IDs in `worker/patch-auto.py`.

Start the emulator from the repository root:

```powershell
.\.venv\Scripts\python.exe .\synthetic_insightvm.py
```

It listens on `http://127.0.0.1:8765` by default. Configure the worker's
InsightVM settings for local testing:

```python
IVM_URL = "http://127.0.0.1:8765"
IVM_USER = "synthetic-user"
IVM_PASS = "synthetic-password"
REPORT_IDS = ["52", "59"]
```

The username and password are accepted for compatibility but are not checked.
For each report ID, the emulator supports the same lifecycle used by the
worker:

1. `POST /api/3/reports/{report_id}/generate`
2. `GET /api/3/reports/{report_id}/history/{instance_id}`
3. `GET /api/3/reports/{report_id}/history/{instance_id}/output`

The generated instance ID is unique for every run, so repeated test runs
exercise report generation and polling rather than relying on a fixed ID.
Unknown report IDs return `404`, which makes invalid report configuration easy
to detect.

The data is synthetic and contains no real asset names, credentials, or
production vulnerability evidence. It covers Windows application and
operating-system findings, SQL Server version classification, TLS findings,
and Red Hat/SSH/ICMP findings. The worker still needs test GitLab and SMTP
configuration (or those integrations should be stubbed) if the full script
entry point is executed.



## Python Automation API
cd worker
uv add fastapi "uvicorn[standard]"
uv run uvicorn api.main:app --host 127.0.0.1 --port 8000