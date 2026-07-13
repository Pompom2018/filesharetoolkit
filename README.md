# FileShareToolkit Portable

All you need for file shares: NTFS ACLs, share permissions, problem ACLs, risk assessment, robocopy planning, dashboard filtering, and user access views.

Portable Windows file share discovery and NTFS permission audit dashboard.

## Run A File Server Scan

```powershell
.\Invoke-FileShareToolkit_Portable_v3_2.ps1 `
  -OutputPath C:\Temp\ShareAudit `
  -MaxAclDepth 1 `
  -CentralJsonPath \\auditserver\ShareAudit\Json `
  -RobocopyDiagnosticDestinationRoot \\netapp\migrationtest\RobocopyDiagnostics `
  -OpenDashboard
```

Each server writes its local run output and copies a central JSON file to the shared folder.

Access diagnostics run automatically when ACL scanning hits inaccessible paths. The rows are aggregated by failing scope and error type, so one bad folder with many child errors becomes one repair target instead of hundreds of duplicate findings.

`-RobocopyDiagnosticDestinationRoot` is optional. When supplied, the toolkit samples the failing scope and runs isolated `robocopy` tests for `/COPY:DAT`, `/COPY:DATS`, and `/COPY:DATSO` into that test folder. Without it, the dashboard still shows ACL, enumeration, owner, SID, and sampled child-file diagnostics.

## Generate The Central Dashboard

```powershell
.\Invoke-FileShareToolkit_Portable_v3_2.ps1 `
  -GenerateCentralDashboard `
  -CentralJsonPath \\auditserver\ShareAudit\Json `
  -OpenDashboard
```

## Publish To GitHub Pages

The central dashboard contains user, ACL, share, and file server data. Only publish it to GitHub Pages when that data is allowed to be visible to the audience of the repository/page.

To generate a Pages-ready `docs/index.html`:

```powershell
.\Invoke-FileShareToolkit_Portable_v3_2.ps1 `
  -GenerateCentralDashboard `
  -CentralJsonPath \\auditserver\ShareAudit\Json `
  -GitHubPagesPath .\docs
```

Then push the repository to GitHub and enable GitHub Pages from the `docs` folder on the main branch.

## NTFS Repair Guidance

Problem ACL rows include a `SuggestedFix` column. The guidance is intentionally conservative:

- Back up ACLs first, for example with `icacls <path> /save <backup-file> /t /c`.
- Do not reset permissions unless you have an approved restore plan.
- For access denied, run elevated or as the file server local admin/SYSTEM first.
- If needed, take ownership only on the affected object, preferably to the Administrators group, then add a temporary admin ACE. This changes ownership/adds access without replacing the existing DACL.
- Remove temporary admin access after cleanup if it is not part of the intended permission model.

The Access Diagnostics tab adds `LikelyCause`, `RecommendedFix`, and robocopy probe results where available:

- `DAT` fails: basic data copy failed; check source access, destination write access, SMB, locks, path length, and storage availability before changing ACLs.
- `DATS` fails after `DAT` succeeds: data can copy, but applying the DACL failed; investigate malformed ACLs, unresolved SIDs, old local accounts, and destination security-style/SID-resolution issues.
- `DATSO` fails after `DAT` and `DATS` succeed: owner preservation is the blocker; use `/COPY:DATS` for the migration pass and repair ownership deliberately where required.

## License And Donations

This repository currently uses the GNU Lesser General Public License v2.1 because that license was selected when the GitHub repo was initialized.

A donation button does not require a special license. Donations can be added separately through GitHub Sponsors or a `.github/FUNDING.yml` file.
