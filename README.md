# IntuneAppInventory

Yes. With the data you're already getting, I would build this as a **small local inventory database + PowerShell GUI + scheduled sync service**, rather than trying to make Entra dynamic groups do the app detection themselves.

One important point first: **the bearer token you pasted is a live access token. Treat it as compromised and obtain a new token.** Don't put the token into the final script or save it in SQLite/log files.

### The design I'd use

```text
                    Microsoft Graph / Intune
                             │
             ┌───────────────┴───────────────┐
             │                               │
       Managed Devices                  Detected Apps
             │                               │
             └───────────────┬───────────────┘
                             │
                       Sync Engine
                             │
                             ▼
                    ┌─────────────────┐
                    │   SQLite DB     │
                    │                 │
                    │ Devices         │
                    │ Applications    │
                    │ DeviceApps      │
                    │ SyncHistory     │
                    │ Groups          │
                    └────────┬────────┘
                             │
                    PowerShell GUI
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
          Search app     Filter version   Find devices
                                             │
                                             ▼
                                      Create/Update
                                      Entra security
                                         group
                                             │
                                             ▼
                                          Intune
                                             │
                                             ▼
                                      App upgrade /
                                         policy
```

This also gives you a good migration path later:

```text
SQLite
   ↓
SQL Server
   ↓
Azure SQL
```

The schema should deliberately be relational so you don't have to redesign everything later.

Microsoft's `detectedApp` object already has `displayName`, `version`, `publisher`, `platform`, `deviceCount`, and a `managedDevices` relationship. ([Microsoft Learn][1])

---

# 1. Database design

I'd use four main tables.

### `Devices`

```text
DeviceId                 Intune managedDevice ID
AzureADDeviceId          Entra device ID
DeviceName
UserPrincipalName
ManagementAgent
OwnerType
ComplianceState
DeviceType
OSVersion
LastSyncDateTime
DeviceRegistrationState
ManagementState
ExchangeAccessState
ExchangeAccessStateReason
Jailbroken
EnrolledDateTime
DeviceEnrollmentType
Notes
LastSeen
```

### `Applications`

```text
AppId
DisplayName
Version
Publisher
Platform
SizeInBytes
DeviceCount
FirstSeen
LastSeen
```

### `DeviceApplications`

This is the important table.

```text
DeviceId
AppId
DetectedVersion
FirstSeen
LastSeen
```

with:

```text
UNIQUE(DeviceId, AppId)
```

That gives you queries such as:

```sql
SELECT
    d.DeviceName,
    d.UserPrincipalName,
    a.DisplayName,
    da.DetectedVersion
FROM DeviceApplications da
JOIN Devices d
    ON d.DeviceId = da.DeviceId
JOIN Applications a
    ON a.AppId = da.AppId
WHERE a.DisplayName = 'Microsoft Edge'
  AND da.DetectedVersion = '151.0.4129.59';
```

Or:

```sql
SELECT
    d.DeviceName,
    d.UserPrincipalName,
    a.DisplayName,
    da.DetectedVersion
FROM DeviceApplications da
JOIN Devices d
    ON d.DeviceId = da.DeviceId
JOIN Applications a
    ON a.AppId = da.AppId
WHERE a.DisplayName LIKE '%Discord%';
```

That is going to become extremely useful once you have thousands of devices.

---

# 2. Don't query detected apps one device at a time

Your current approach is:

```text
Get all devices
    ↓
for each device
    ↓
GET /managedDevices/{id}/detectedApps
```

That works, but it will become unnecessarily expensive as your environment grows.

The Graph API exposes the detected-app collection globally:

```text
GET /deviceManagement/detectedApps
```

and each detected app has a `managedDevices` relationship. ([Microsoft Learn][2])

So I'd build the inventory around:

```text
GET /deviceManagement/managedDevices
```

and

```text
GET /deviceManagement/detectedApps
```

then use:

```text
GET /deviceManagement/detectedApps/{detectedAppId}/managedDevices
```

when we need to establish the app → device relationship.

That is much more scalable.

---

# 3. Very important: Intune group vs Entra group

For what you're describing, I would create a **Microsoft Entra security group** and then assign the Intune application to that group.

For example:

```text
APP-UPGRADE | Microsoft Edge | 151.0.4129.59
```

or preferably:

```text
INTUNE-APP-MicrosoftEdge-v151.0.4129.59
```

Members:

```text
MSI-PC1
MSI-W11-DESKTOP
PW0NS62K
...
```

The group is then available to Intune for application assignment.

Microsoft Graph supports devices as members of security groups, and members can be added through `/groups/{group-id}/members/$ref`. ([Microsoft Learn][3])

This should be a **static security group maintained by your inventory service**, rather than an Entra dynamic group.

That's actually a better fit for your requirement because **Intune discovered-app data isn't an Entra dynamic-group attribute**.

---

# 4. The GUI I'd build

I'd make the PowerShell application look roughly like this:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                    Intune Application Inventory                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ [ Refresh Inventory ] [ Sync Now ] [ Create Group ] [ Settings ]       │
│                                                                         │
│ Application: [ Microsoft Edge                         ▼ ]               │
│ Version:     [ 151.0.4129.59                         ▼ ]               │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ Application             Version              Publisher        Devices   │
│ ─────────────────────────────────────────────────────────────────────  │
│ Microsoft Edge          151.0.4129.59        Microsoft         14      │
│ Microsoft Edge          150.0.4099.10        Microsoft         38      │
│ Discord                 1.0.9251             Discord Inc.       7      │
│ Fortnite                41.30                 Epic Games         2      │
│ Logitech G HUB          2026.4.919028        Logitech            4      │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ Selected application                                                      │
│                                                                         │
│ Microsoft Edge                                                           │
│ Version: 151.0.4129.59                                                   │
│ Devices: 14                                                              │
│                                                                         │
│ [ View Devices ]   [ Create Intune Group ]                              │
└─────────────────────────────────────────────────────────────────────────┘
```

Then clicking **View Devices**:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ Devices running Microsoft Edge 151.0.4129.59                            │
├─────────────────────────────────────────────────────────────────────────┤
│ ☑ Device          User                    OS             Last Sync       │
│ ──────────────────────────────────────────────────────────────────────  │
│ ☑ MSI-PC1         abdul@qayyum.uk         Windows 11     08/08 12:34   │
│ ☑ MSI-W11-DESKTOP abdul@qayyum.uk         Windows 11     08/08 16:44   │
│ ☑ PW0NS62K        abdul@qayyum.uk         Windows 11     08/08 18:20   │
│                                                                         │
│ 3 devices                                                                │
│                                                                         │
│ [ Create Group From Results ]                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

And then:

```text
Create Intune Target Group

Application:
Microsoft Edge

Detected version:
151.0.4129.59

Devices:
14

Group name:
[ INTUNE-APP-MicrosoftEdge-v151.0.4129.59 ]

Description:
[ Devices detected with Microsoft Edge 151.0.4129.59 ]

☑ Automatically maintain membership during sync

                         [ Cancel ] [ Create Group ]
```

---

# 5. The sync engine

The hourly job should do this:

```text
START
  │
  ├── Authenticate
  │
  ├── Get managed devices
  │
  ├── Upsert Devices
  │
  ├── Get detected applications
  │
  ├── Upsert Applications
  │
  ├── Get devices for each detected application
  │
  ├── Upsert DeviceApplications
  │
  ├── Mark records not seen in this sync
  │
  ├── Update existing application groups
  │
  └── Write SyncHistory
```

I'd also put a `SyncId`/timestamp on every run.

That gives you:

```text
Last sync:       20:00
Devices:         2,341
Applications:    18,927
Relationships:   146,288
Duration:        00:04:17
Status:          Success
```

---

# 6. Group maintenance

This is where the solution becomes particularly useful.

Suppose you create:

```text
INTUNE-APP-Discord-v1.0.9251
```

The database says:

```text
Discord
1.0.9251

Device A
Device B
Device C
```

The service compares that against the actual Entra group:

```text
Desired members
       vs
Current members
```

Then:

```text
Desired             Current

A                    A
B                    B
C                    D
                     E
```

The service performs:

```text
ADD C
REMOVE D
REMOVE E
```

So the group is continuously maintained.

This is much better than recreating groups every hour.

---

# 7. The critical ID mapping

Your Intune managed-device ID is:

```text
2bab7fef-a8a5-458f-854b-3d0de8f6167f
```

But the Entra device membership requires the **Entra device object ID**.

So when collecting devices I'd add:

```text
azureADDeviceId
```

to your `$select`.

For example:

```powershell
$select = @(
    'id'
    'azureADDeviceId'
    'deviceName'
    'userPrincipalName'
    'managementAgent'
    'ownerType'
    'complianceState'
    'deviceType'
    'osVersion'
    'lastSyncDateTime'
    'deviceRegistrationState'
    'managementState'
    'exchangeAccessState'
    'exchangeAccessStateReason'
    'jailbroken'
    'enrolledDateTime'
    'deviceEnrollmentType'
    'notes'
) -join ','
```

That gives the inventory database both identifiers:

```text
Intune Managed Device ID
        │
        │
        ▼
Azure AD / Entra Device ID
```

This is essential for group management.

---

# 8. Your current query should also be cleaned up

The URLs in your pasted PowerShell contain Markdown artifacts:

```text
[https://graph.microsoft.com/...](https://graph.microsoft.com/...)
```

Those aren't valid PowerShell URLs.

Use normal strings:

```powershell
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
```

Also, I'd stop hard-coding:

```powershell
$top=50
```

and `$skipToken`.

Instead, build a reusable Graph pagination function that follows:

```text
@odata.nextLink
```

until there are no more pages.

That will make the database sync independent of whether you have:

```text
50 devices
500 devices
5,000 devices
50,000 devices
```

---

# 9. SQLite schema

I'd start with this:

```sql
CREATE TABLE IF NOT EXISTS Devices (
    DeviceId TEXT PRIMARY KEY,
    AzureADDeviceId TEXT,
    DeviceName TEXT,
    UserPrincipalName TEXT,
    ManagementAgent TEXT,
    OwnerType TEXT,
    ComplianceState TEXT,
    DeviceType TEXT,
    OSVersion TEXT,
    LastSyncDateTime TEXT,
    DeviceRegistrationState TEXT,
    ManagementState TEXT,
    ExchangeAccessState TEXT,
    ExchangeAccessStateReason TEXT,
    Jailbroken TEXT,
    EnrolledDateTime TEXT,
    DeviceEnrollmentType TEXT,
    Notes TEXT,
    FirstSeen TEXT NOT NULL,
    LastSeen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Applications (
    AppId TEXT PRIMARY KEY,
    DisplayName TEXT NOT NULL,
    Version TEXT,
    Publisher TEXT,
    Platform TEXT,
    SizeInBytes INTEGER,
    DeviceCount INTEGER,
    FirstSeen TEXT NOT NULL,
    LastSeen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS DeviceApplications (
    DeviceId TEXT NOT NULL,
    AppId TEXT NOT NULL,
    DetectedVersion TEXT,
    FirstSeen TEXT NOT NULL,
    LastSeen TEXT NOT NULL,
    PRIMARY KEY (DeviceId, AppId),
    FOREIGN KEY (DeviceId) REFERENCES Devices(DeviceId),
    FOREIGN KEY (AppId) REFERENCES Applications(AppId)
);

CREATE TABLE IF NOT EXISTS ManagedGroups (
    GroupId TEXT PRIMARY KEY,
    GroupName TEXT NOT NULL,
    AppId TEXT,
    AppName TEXT,
    AppVersion TEXT,
    Enabled INTEGER NOT NULL DEFAULT 1,
    LastSync TEXT
);

CREATE TABLE IF NOT EXISTS SyncHistory (
    SyncId TEXT PRIMARY KEY,
    Started TEXT NOT NULL,
    Completed TEXT,
    DeviceCount INTEGER,
    ApplicationCount INTEGER,
    RelationshipCount INTEGER,
    Status TEXT,
    ErrorMessage TEXT
);
```

Then create indexes:

```sql
CREATE INDEX IF NOT EXISTS IX_Applications_DisplayName
ON Applications(DisplayName);

CREATE INDEX IF NOT EXISTS IX_Applications_Version
ON Applications(Version);

CREATE INDEX IF NOT EXISTS IX_DeviceApplications_App
ON DeviceApplications(AppId);

CREATE INDEX IF NOT EXISTS IX_DeviceApplications_Device
ON DeviceApplications(DeviceId);

CREATE INDEX IF NOT EXISTS IX_Devices_Name
ON Devices(DeviceName);

CREATE INDEX IF NOT EXISTS IX_Devices_User
ON Devices(UserPrincipalName);
```

---

# 10. The queries you'll eventually be able to run

### Exact application/version

```sql
SELECT
    d.DeviceName,
    d.UserPrincipalName,
    d.OSVersion,
    d.LastSyncDateTime
FROM DeviceApplications da
JOIN Devices d ON d.DeviceId = da.DeviceId
JOIN Applications a ON a.AppId = da.AppId
WHERE a.DisplayName = 'Microsoft Edge'
AND da.DetectedVersion = '151.0.4129.59'
ORDER BY d.DeviceName;
```

### All devices with an application

```sql
SELECT
    d.DeviceName,
    d.UserPrincipalName,
    a.DisplayName,
    da.DetectedVersion
FROM DeviceApplications da
JOIN Devices d ON d.DeviceId = da.DeviceId
JOIN Applications a ON a.AppId = da.AppId
WHERE a.DisplayName = 'Discord'
ORDER BY d.DeviceName;
```

### Devices below a version

This gets interesting because application versions aren't always safely comparable as strings, so I'd initially do the filtering in PowerShell using a version-aware comparison where possible.

For example:

```text
Chrome < target
Edge < target
7-Zip < target
```

and produce:

```text
Application       Installed       Target
Microsoft Edge    150.x           151.x
Microsoft Edge    149.x           151.x
Microsoft Edge    151.x           151.x
```

Then:

```text
CREATE GROUP
```

only selects the devices below target.

---

# 11. I would actually make the GUI support three modes

### Mode 1 — Inventory

```text
Applications
    ↓
versions
    ↓
devices
```

### Mode 2 — Targeting

```text
Application
Version condition
       ↓
Matching devices
       ↓
Entra security group
       ↓
Intune assignment
```

### Mode 3 — Compliance / upgrade

Eventually:

```text
Microsoft Edge

Target: 151.0.4129.59

Installed:
151.x       1,240
150.x         183
149.x          42
Unknown        11
```

Then the GUI can say:

```text
1,466 devices require upgrade

[ Create Upgrade Group ]
```

---

# 12. Hourly scheduling

I wouldn't put the hourly timer inside the GUI itself.

Instead have:

```text
IntuneInventory.ps1
```

with modes:

```powershell
.\IntuneInventory.ps1 -Sync
```

and:

```powershell
.\IntuneInventory.ps1 -Gui
```

The GUI is interactive.

The scheduler runs:

```text
IntuneInventory.ps1 -Sync
```

every hour.

That means the database continues updating even when the GUI isn't open.

You can create a Windows Scheduled Task:

```text
Task Scheduler
   └── Intune Inventory Sync
          ├── Every 1 hour
          └── powershell.exe
                 └── IntuneInventory.ps1 -Sync
```

---

# 13. Authentication

I would **not** use the `$token` approach for the finished system.

Your interactive GUI can use delegated authentication.

Your hourly scheduled task should use an **Entra application/service principal**, preferably certificate authentication rather than a client secret.

The application needs the appropriate Microsoft Graph permissions. The detected-app API documents `DeviceManagementManagedDevices.Read.All` as an application permission for reading detected apps. ([Microsoft Learn][2])

For the group-management side, you'll need appropriate directory/group permissions because the service will create security groups and add/remove devices. Graph supports adding devices to security groups via the group members relationship. ([Microsoft Learn][3])

---

# 14. One thing I'd change from your original plan

Don't make a group for **every application/version automatically**.

You'll potentially end up with:

```text
10,000 applications
×
multiple versions
=
tens of thousands of groups
```

Instead, have the GUI allow you to designate an application as a **managed target**.

For example:

```text
Inventory
────────────────────────────
Microsoft Edge
Discord
Fortnite
7-Zip
Adobe Acrobat
...
```

You select:

```text
Microsoft Edge
```

Then:

```text
Target version:
151.0.4129.59

Condition:
[ Installed version < target ]

Group:
INTUNE-UPGRADE-MicrosoftEdge-151-0-4129-59
```

Now the hourly sync maintains only the groups you've actually chosen to manage.

That keeps the tenant clean.

---

## The finished system

I'd structure the project like this:

```text
C:\ProgramData\IntuneInventory\
│
├── IntuneInventory.ps1
├── IntuneInventory.db
├── config.json
│
├── Modules\
│   ├── Graph.psm1
│   ├── SQLite.psm1
│   ├── Inventory.psm1
│   ├── Groups.psm1
│   └── GUI.psm1
│
└── Logs\
    ├── Sync.log
    └── Error.log
```

And ultimately the GUI:

```text
┌───────────────────────────────────────────────────────────┐
│ Intune Application Inventory                              │
├───────────────────────────────────────────────────────────┤
│ [Applications] [Devices] [Upgrade Groups] [Sync] [Config] │
├───────────────────────────────────────────────────────────┤
│ Search: [ edge                                      ] 🔍  │
│                                                           │
│ Microsoft Edge                                            │
│ ├─ 151.0.4129.59                 14 devices                │
│ ├─ 150.0.4099.10                 38 devices                │
│ └─ 149.x                          6 devices                │
│                                                           │
│ Selected: Microsoft Edge 151.0.4129.59                   │
│                                                           │
│ [View Devices] [Create Target Group] [Export CSV]         │
└───────────────────────────────────────────────────────────┘
```

**This is very achievable with PowerShell + SQLite + Microsoft Graph**, and your existing Graph queries are a good starting point. The key change is to make the database the source for your reporting and group-selection logic, while Graph/Intune remains the source of truth.

I can build the **actual single-file `IntuneInventory.ps1` application next**, including the WinForms GUI, SQLite initialization, Graph pagination, full device/app sync, application/version search, Entra group creation, membership reconciliation, CSV export, and `-Sync` mode for the hourly Scheduled Task.

[1]: https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-detectedapp?view=graph-rest-1.0&utm_source=chatgpt.com "detectedApp resource type - Microsoft Graph v1.0 | Microsoft Learn"
[2]: https://learn.microsoft.com/en-us/graph/api/intune-devices-detectedapp-list?view=graph-rest-1.0&utm_source=chatgpt.com "List detectedApps - Microsoft Graph v1.0 | Microsoft Learn"
[3]: https://learn.microsoft.com/ka-ge/graph/api/group-post-members?view=graph-rest-1.0&utm_source=chatgpt.com "Add members - Microsoft Graph v1.0 | Microsoft Learn"


Application version distribution

Illustrative view of how the inventory UI could visualize detected application versions.

version	devices
151.x	1,240
150.x	183
149.x	42
Unknown	11
