# `patch-auto.py` — Detailed Summary

## 1. Purpose

`patch-auto.py` is an automated vulnerability-report processing and remediation-preparation script. It connects to Rapid7 InsightVM, generates vulnerability reports for selected report IDs, converts the CSV results into structured asset and vulnerability data, groups findings into remediation categories, creates Ansible inventory/control files and JSON job files, publishes selected files to GitLab, and sends email notifications.

The script prepares the information needed for remediation; it does not directly patch servers itself. The generated inventories and job files are intended to be consumed by Ansible Tower or another scheduled automation process. The email messages explicitly tell recipients to review the files, verify the Tower jobs, and confirm maintenance windows.

At the time of review, the active report IDs are:

- `52` — BI
- `59` — DE

Other report IDs are present in the configuration but commented out, so they are not processed unless uncommented.

## 2. End-to-end workflow

When run as a program, the script performs this sequence:

1. It loops through every active InsightVM report ID.
2. It requests InsightVM to generate a fresh report.
3. It polls the report-history endpoint until the report is complete, failed, or times out.
4. It downloads the completed CSV report.
5. It parses each CSV row and extracts the asset IP, hostname, operating-system information, vulnerability title, severity, remediation solution, and vulnerability proof.
6. It maps each vulnerability to a remediation category using operating-system and vulnerability-title rules.
7. It creates a master asset map containing all findings from all reports.
8. It removes duplicate findings when the same IP appears in multiple reports.
9. It builds category-specific remediation jobs, selecting the highest severity found for each host/category pair.
10. It writes Windows and Linux Ansible inventories.
11. It writes one JSON job file per category and two remediation-control JSON files.
12. It uploads the generated inventory files to the configured GitLab project and branch.
13. It creates per-report/team inventory files and uploads those inventory files to GitLab as well.
14. It sends one aggregate email with the generated files attached.
15. It sends a separate summary email for each processed report that has a team configuration.
16. It prints a completion message explaining that Tower is expected to run the patching on its configured schedule.

If no usable assets are extracted from any report, the script prints an error and exits with status code `1`.

## 3. Configuration and external systems

### InsightVM

The InsightVM configuration defines:

- The InsightVM API base URL.
- A username and password used for HTTP Basic Authentication.
- The report IDs to process.

The script disables TLS certificate warnings globally and sends InsightVM requests with certificate verification disabled. This allows connections to an internal server with an untrusted or self-signed certificate, but it also means the connection is not protected by normal certificate validation.

### GitLab

The GitLab configuration defines:

- The GitLab server URL.
- A private access token.
- The project ID.
- The target branch, currently `develop`.

The upload function uses the GitLab Repository Files API. It first checks whether the target file exists on the branch:

- If the file exists, it sends `PUT` to replace it.
- If the file does not exist, it sends `POST` to create it.

Each upload uses a commit message containing the path of the updated file. The script uploads inventory files, but the upload calls for category JSON files and remediation-control JSON files are currently commented out.

### Email

The email configuration defines:

- An internal SMTP server and port.
- The sender address.
- The aggregate recipient list.
- The email subject template.
- A report-to-team mapping containing team names and recipient lists.

The script sends email without SMTP authentication or encryption. It creates both plain-text and HTML alternatives so that email clients that cannot render HTML still receive the report.

## 4. Category model

The script separates categories into two groups:

- `WINDOWS_CATEGORIES`
- `LINUX_CATEGORIES`

The category sets control which findings are included in Windows and Linux inventories. The friendly-name map, `CATEGORY_NAMES`, is used only for human-readable email labels.

### Windows application and product categories

The script recognizes findings for products such as:

- Google Chrome
- Mozilla Firefox
- Microsoft Edge
- Wireshark
- Notepad++
- Cisco Jabber
- WinRAR
- 7-Zip
- WinSCP
- Java/JRE
- Microsoft VS Code
- VMware Tools
- Microsoft Silverlight
- Microsoft MSXML 4
- Microsoft .NET Framework
- Microsoft Defender
- Microsoft SQL Server

### Windows operating-system and protocol categories

It also recognizes:

- Windows Server 2016 operating-system CVEs
- Windows Server 2019 operating-system CVEs
- Windows Server 2022 operating-system CVEs
- CVE-2013-3900
- Intel Branch History Injection / CVE-2022-0001
- TLS 1.0 and TLS 1.1 issues
- SWEET32/3DES issues
- Weak TLS HMAC cipher suites
- Static TLS key cipher suites
- Unencrypted FTP
- NetBIOS NBSTAT traffic amplification
- Specific Visual Studio information-disclosure vulnerabilities

### Linux categories

Linux classification is limited to Red Hat Enterprise Linux versions beginning with `8` or `9`. It recognizes:

- Red Hat operating-system CVEs
- Weak SSH HMAC algorithms
- SSH CBC cipher weaknesses
- Weak SSH key-exchange algorithms
- ICMP redirection enabled

Any finding that does not match one of the explicit rules is assigned to `other`. The `other` category is retained in the internal asset data but excluded from the detected remediation-category list and from the generated inventories.

## 5. CSV parsing and asset data

`extract_assets()` expects an InsightVM CSV with fields including:

- `Asset IP Address`
- `Asset Names`
- `Asset OS Name`
- `Asset OS Version`
- `Vulnerability Title`
- `Severity`
- `Solution` or `Vulnerability Solution`
- `Vulnerability Proof` or `Proof`

The first hostname is used when the `Asset Names` column contains multiple comma-separated names. Missing hostnames default to `unknown`, and missing severities default to `Unknown`.

Rows without an IP address or vulnerability title are ignored.

Internally, each IP is represented approximately as:

```text
{
  hostname,
  ip,
  os,
  os_version,
  categories: {
    category: [
      {
        title,
        severity,
        solution
      }
    ]
  }
}
```

The vulnerability proof is used to detect the SQL Server version, but it is not written into the stored vulnerability object or any generated JSON job. This means the proof helps classification but is not preserved in the output artifacts.

## 6. SQL Server version handling

SQL findings are first assigned to the general `sql` category. The script then searches the vulnerability proof for text matching:

```text
Microsoft SQL Server YYYY
```

When a four-digit year is found, the same finding is added to an additional category such as:

- `sql2012`
- `sql2014`
- `sql2016`
- `sql2017`
- `sql2019`
- `sql2022`

This is additive rather than replacing the general `sql` category. Therefore, a SQL finding can appear in both the general SQL jobs and the version-specific jobs.

## 7. Combining multiple reports and de-duplication

The script maintains two views of the data:

1. `report_asset_map`: the assets belonging to each individual report, used for team-specific inventories and emails.
2. `assets`: a master merged collection across all active reports, used for aggregate remediation files.

When two reports contain the same IP, the script merges their categories and findings. A duplicate is identified using the combination of:

- Vulnerability title
- Severity
- Solution

This prevents the same finding from being appended repeatedly when it appears in more than one report. Hostname and operating-system metadata come from the first copy initially stored for that IP.

## 8. Remediation job generation

`build_category_jobs()` creates a simplified job entry for every host that belongs to a requested category. Each job contains:

- Hostname
- IP address
- Operating-system name
- Operating-system version
- Remediation category
- Number of vulnerabilities in that category
- Highest severity in that category
- Title of the highest-severity vulnerability

Severity ranking is:

1. Critical
2. High
3. Medium
4. Low
5. Unknown

The function does not include the complete list of vulnerability titles or solutions in the job entry. The category JSON files therefore provide a compact host-level remediation summary rather than a complete raw export.

## 9. Generated files

### Per-category JSON files

For every detected category with matching jobs, the script writes:

```text
inventory/<category>_jobs.json
```

for Windows categories, or:

```text
l_inventory/<category>_jobs.json
```

for Linux categories.

Each file contains the list returned by `build_category_jobs()`. The directories are created automatically if necessary.

### Windows inventory

The aggregate Windows inventory is written to:

```text
inventory/remediation_inventory.ini
```

It contains:

- One Ansible group per Windows remediation category.
- Hostnames under each category group.
- An `all_windows:children` group containing all selected category groups.
- An `all_windows:vars` section with a comma-separated `remediation_categories` variable.

Windows inventory entries use hostnames rather than IP addresses.

### Linux inventory

The aggregate Linux inventory is written to:

```text
l_inventory/l_remediation_inventory.ini
```

It has the same group structure, but Linux entries use IP addresses instead of hostnames. Its parent group is `linux`.

### Remediation-control files

The script writes:

```text
inventory/remediation_control.json
l_inventory/l_remediation_control.json
```

Each file contains a JSON object with a sorted `remediation_categories` array. The Windows control file includes only detected Windows categories, and the Linux control file includes only detected Linux categories.

These files are currently generated locally but are not uploaded to GitLab because their upload calls are commented out.

### Per-team inventories

For every report with categorized findings, the script creates a team-specific inventory when appropriate:

```text
inventory/<team_slug>_remediation_inventory.ini
l_inventory/<team_slug>_l_remediation_inventory.ini
```

The team slug is generated by lowercasing the configured team name and replacing spaces with underscores. These files are uploaded to GitLab.

## 10. Aggregate email

`send_email()` sends the main report email to the addresses in `EMAIL_TO`.

The message includes:

- The report date and time.
- A plain-text summary.
- A warning that unremediated assets will be automatically patched after 14 days.
- The next-step instructions for reviewing inventories and Ansible Tower jobs.
- An HTML category table showing the friendly category name and affected-host count.
- Every path in the `generated_files` list as an attachment, provided the file exists.

The email counts are based on category job counts. A host that appears in multiple categories contributes to more than one category count, so the `total_hosts` value is a count of host-category hits rather than necessarily a count of unique hosts.

## 11. Team summary emails

`send_report_summary_email()` creates a separate email for each processed report ID that exists in `REPORT_EMAILS`.

The message:

- Identifies the configured team.
- Groups affected hostnames and IP addresses by remediation category.
- Displays category counts and a 14-day automatic-patching warning.
- Uses both plain text and table-based HTML.
- Attaches the team-specific inventory files created for that report.

The function skips the `other` category in the email because it is not an actionable remediation category. It sends to exactly the recipient list configured for the report. Several configured reports have empty recipient lists or commented-out recipients, so those emails may be generated with no effective recipients if those report IDs are enabled.

## 12. Important implementation details and limitations

### Security-sensitive configuration

The script contains credentials and access tokens directly in source code. This is a serious security risk because anyone who can read the file may be able to access InsightVM or GitLab. Those credentials should be rotated and moved to environment variables, a secret manager, or a protected configuration mechanism.

### TLS verification is disabled

InsightVM and GitLab requests pass `verify=False`, and the script suppresses the resulting warnings. This prevents certificate validation and makes man-in-the-middle attacks more difficult to detect. Proper internal certificates and certificate verification should be used where possible.

### No request timeout is configured

The HTTP requests do not specify request timeouts. A network problem could cause the script to wait indefinitely. Explicit connect and read timeouts would make scheduled execution more predictable.

### Limited API error handling

The report-generation and download paths check status codes, but many JSON parsing and network exceptions are not handled locally. An unexpected response shape or connection exception can terminate the run.

### Email failures do not fail the job

Both email functions catch broad exceptions and print an error. The script then continues and can still print its final completion message. This means an operational run may appear complete even when notifications were not delivered.

### Inventory uploads and local outputs can diverge

The inventory files are uploaded to GitLab, but category JSON and remediation-control JSON upload calls are commented out. GitLab therefore does not necessarily contain all locally generated artifacts.

### Category rules are exact-prefix based

Many mappings use `startswith()`. A title variation, capitalization change, different vendor naming convention, or changed InsightVM wording can cause a vulnerability to fall into `other` and therefore be excluded from remediation outputs.

### Windows and Linux detection is narrow

Windows rules generally require the OS name to start with `Microsoft Windows Server`. Linux rules require Red Hat Enterprise Linux 8 or 9. Other Windows editions, other Linux distributions, and newer or older Red Hat versions may not be classified.

### The script prepares remediation but does not execute it

There is no direct Ansible Tower API call or patch execution in this file. It creates the inventory/job inputs and sends instructions for Tower to execute them according to its own schedule.

## 13. Commented or inactive code

The file contains an earlier email implementation that is fully commented out. It documents a previous plain-text email format and references older attachment names and a seven-day warning. It has no runtime effect.

There are also commented-out alternatives for:

- Report IDs that are not currently active.
- Older Windows OS categorization logic.
- An earlier implementation of inventory creation.
- Uploading JSON and remediation-control files to GitLab.
- Some recipient addresses.

Only uncommented Python statements affect the current run.

## 14. Required runtime dependencies and assumptions

The script requires Python 3 and these third-party/runtime capabilities:

- `requests`
- Access to the InsightVM API endpoint
- Access to the GitLab API endpoint
- Access to the configured SMTP server
- Permission to create `inventory` and `l_inventory` directories
- Permission to write the generated files

The working directory matters because the script writes relative paths such as `inventory/...` and `l_inventory/...`. It should be run from the project directory, or the output paths should be converted to paths based on the script location.

## 15. Plain-language conclusion

In short, `patch-auto.py` is a bridge between vulnerability scanning and scheduled remediation. InsightVM is the source of vulnerability data, the script translates scanner findings into product/OS/protocol categories, the generated INI and JSON files are the remediation inputs, GitLab acts as a repository for the inventories, and email provides operational visibility to the security and application teams. Ansible Tower is expected to consume the inventories and carry out the actual patching on its configured schedule.