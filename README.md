# FileShareToolkit Portable

All you need for file shares: NTFS ACLs, share permissions, problem ACLs, risk assessment, robocopy planning, dashboard filtering, and user access views.

Portable Windows file share discovery and NTFS permission audit dashboard.

## Run A File Server Scan

```powershell
.\Invoke-FileShareToolkit_Portable_v3_2.ps1 `
  -OutputPath C:\Temp\ShareAudit `
  -MaxAclDepth 1 `
  -CentralJsonPath \\auditserver\ShareAudit\Json `
  -OpenDashboard
```

Each server writes its local run output and copies a central JSON file to the shared folder.

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

## License And Donations

This repository currently uses the GNU Lesser General Public License v2.1 because that license was selected when the GitHub repo was initialized.

A donation button does not require a special license. Donations can be added separately through GitHub Sponsors or a `.github/FUNDING.yml` file.
