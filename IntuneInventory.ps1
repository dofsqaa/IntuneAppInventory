<#
.SYNOPSIS
    Intune Application Inventory Engine & Entra ID Security Group Sync Utility.
.DESCRIPTION
    Extracts Intune managed devices and detected applications via Microsoft Graph,
    populates a local relational SQLite database, provides a full management GUI,
    and reconciles targeted Entra ID Security Groups for dynamic app deployments.
.EXAMPLE
    # Launch Interactive GUI
    .\IntuneInventory.ps1 -Gui

    # Execute Hourly Sync (for Scheduled Task)
    .\IntuneInventory.ps1 -Sync
#>

[CmdletBinding()]
param(
    [Switch]$Sync,
    [Switch]$Gui,
    [String]$ConfigPath = "$PSScriptRoot\config.json"
)

# -----------------------------------------------------------------------------
# 1. CORE SYSTEM CONFIGURATION & INITIALIZATION
# -----------------------------------------------------------------------------
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$AppRoot = "C:\ProgramData\IntuneInventory"
if (-not (Test-Path $AppRoot)) { New-Item -Path $AppRoot -ItemType Directory -Force | Out-Null }
$LogDir = Join-Path $AppRoot "Logs"
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }

$DbPath   = Join-Path $AppRoot "IntuneInventory.db"
$LogPath  = Join-Path $LogDir "Sync.log"
$ErrorLog = Join-Path $LogDir "Error.log"

function Write-Log {
    param([String]$Message, [ValidateSet("INFO", "WARN", "ERROR")]$Level = "INFO")
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "[$Stamp] [$Level] $Message"
    Write-Output $Line
    Add-Content -Path $LogPath -Value $Line -ErrorAction SilentlyContinue
}

# Load Configuration
if (-not (Test-Path $ConfigPath)) {
    $DefaultConfig = @{
        TenantId     = "YOUR_TENANT_ID"
        ClientId     = "YOUR_CLIENT_ID"
        CertThumb    = "YOUR_CERT_THUMBPRINT"
        ClientSecret = "" # Optional fallback if cert not used
    } | ConvertTo-Json -Depth 4
    Set-Content -Path $ConfigPath -Value $DefaultConfig
    Write-Log "Created default config.json at $ConfigPath. Please configure authentication settings." "WARN"
}

$Config = Get-Content -Path $ConfigPath | ConvertFrom-Json

# -----------------------------------------------------------------------------
# 2. SQLITE ASSEMBLY BOOTSTRAPPER
# -----------------------------------------------------------------------------
function Initialize-SQLite {
    if (-not ('System.Data.SQLite.SQLiteConnection' -as [type])) {
        $DLLPath = Join-Path $AppRoot "System.Data.SQLite.dll"
        if (-not (Test-Path $DLLPath)) {
            Write-Log "Downloading System.Data.SQLite binary driver..." "INFO"
            $PkgUrl = "https://www.nuget.org/api/v2/package/System.Data.SQLite.Core/1.0.118"
            $ZipPath = Join-Path $AppRoot "sqlite_pkg.zip"
            Invoke-WebRequest -Uri $PkgUrl -OutFile $ZipPath
            Expand-Archive -Path $ZipPath -DestinationPath (Join-Path $AppRoot "sqlite_extracted") -Force
            
            $FoundDll = Get-ChildItem -Path (Join-Path $AppRoot "sqlite_extracted") -Filter "System.Data.SQLite.dll" -Recurse | 
                        Where-Path -Like "*net46*" | Select-Object -First 1
            if ($FoundDll) {
                Copy-Item -Path $FoundDll.FullName -Destination $DLLPath -Force
                # Native interop dll download/placement
                $NativeDir = Join-Path $AppRoot "x64"
                if (-not (Test-Path $NativeDir)) { New-Item -Path $NativeDir -ItemType Directory | Out-Null }
                $NativeDll = Get-ChildItem -Path (Join-Path $AppRoot "sqlite_extracted") -Filter "SQLite.Interop.dll" -Recurse | 
                             Where-Path -Like "*x64*" | Select-Object -First 1
                if ($NativeDll) { Copy-Item -Path $NativeDll.FullName -Destination (Join-Path $NativeDir "SQLite.Interop.dll") -Force }
            }
            Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
            Remove-Item (Join-Path $AppRoot "sqlite_extracted") -Recurse -Force -ErrorAction SilentlyContinue
        }
        [System.Reflection.Assembly]::LoadFrom($DLLPath) | Out-Null
    }
}

Initialize-SQLite

function Invoke-SQLiteQuery {
    param(
        [Parameter(Mandatory=$true)][String]$Query,
        [Hashtable]$Parameters = @{},
        [Switch]$AsScalar,
        [Switch]$NonQuery
    )
    $ConnStr = "Data Source=$DbPath;Version=3;Pooling=True;Max Pool Size=100;"
    $Conn = New-Object System.Data.SQLite.SQLiteConnection($ConnStr)
    $Conn.Open()
    try {
        $Cmd = $Conn.CreateCommand()
        $Cmd.CommandText = $Query
        foreach ($Key in $Parameters.Keys) {
            $Cmd.Parameters.AddWithValue("@$Key", $Parameters[$Key]) | Out-Null
        }
        
        if ($NonQuery) {
            return $Cmd.ExecuteNonQuery()
        }
        elseif ($AsScalar) {
            return $Cmd.ExecuteScalar()
        }
        else {
            $Adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($Cmd)
            $DS = New-Object System.Data.DataSet
            $Adapter.Fill($DS) | Out-Null
            return $DS.Tables[0]
        }
    }
    finally {
        $Conn.Close()
        $Conn.Dispose()
    }
}

function Initialize-DatabaseSchema {
    $Schema = @"
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
        ComparisonOperator TEXT DEFAULT 'EQUALS',
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

    CREATE INDEX IF NOT EXISTS IX_Applications_DisplayName ON Applications(DisplayName);
    CREATE INDEX IF NOT EXISTS IX_Applications_Version ON Applications(Version);
    CREATE INDEX IF NOT EXISTS IX_DeviceApplications_App ON DeviceApplications(AppId);
    CREATE INDEX IF NOT EXISTS IX_DeviceApplications_Device ON DeviceApplications(DeviceId);
    CREATE INDEX IF NOT EXISTS IX_Devices_Name ON Devices(DeviceName);
    CREATE INDEX IF NOT EXISTS IX_Devices_User ON Devices(UserPrincipalName);
"@
    Invoke-SQLiteQuery -Query $Schema -NonQuery
}

Initialize-DatabaseSchema

# -----------------------------------------------------------------------------
# 3. MICROSOFT GRAPH AUTHENTICATION & ENGINE HELPERS
# -----------------------------------------------------------------------------
$Global:GraphToken = $null

function Get-GraphAccessToken {
    if ($Global:GraphToken) { return $Global:GraphToken }
    
    $Scope = "https://graph.microsoft.com/.default"
    $Url = "https://login.microsoftonline.com/$($Config.TenantId)/oauth2/v2.0/token"

    if (-not [string]::IsNullOrEmpty($Config.CertThumb)) {
        $Cert = Get-Item "Cert:\LocalMachine\My\$($Config.CertThumb)" -ErrorAction SilentlyContinue
        if (-not $Cert) { $Cert = Get-Item "Cert:\CurrentUser\My\$($Config.CertThumb)" }
        if (-not $Cert) { throw "Certificate with thumbprint $($Config.CertThumb) was not found." }

        # Build JWT Client Assertion
        $Header = @{ alg = "RS256"; typ = "JWT"; x5t = [Convert]::ToBase64String($Cert.GetCertHash()) } | ConvertTo-Json -Compress
        $Now = [DateTimeOffset]::UtcNow
        $Payload = @{
            aud = $Url
            exp = $Now.AddMinutes(10).ToUnixTimeSeconds()
            iss = $Config.ClientId
            jti = [Guid]::NewGuid().ToString()
            nbf = $Now.ToUnixTimeSeconds()
            sub = $Config.ClientId
        } | ConvertTo-Json -Compress

        $Base64Header  = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Header)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $Base64Payload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Payload)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $SignatureInput = "$Base64Header.$Base64Payload"

        $RSACSP = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
        $SignatureBytes = $RSACSP.SignData([System.Text.Encoding]::UTF8.GetBytes($SignatureInput), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $Base64Signature = [Convert]::ToBase64String($SignatureBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')

        $Assertion = "$SignatureInput.$Base64Signature"
        $Body = @{
            client_id             = $Config.ClientId
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            client_assertion      = $Assertion
            scope                 = $Scope
            grant_type            = "client_credentials"
        }
    }
    else {
        $Body = @{
            client_id     = $Config.ClientId
            client_secret = $Config.ClientSecret
            scope         = $Scope
            grant_type    = "client_credentials"
        }
    }

    $Response = Invoke-RestMethod -Uri $Url -Method Post -Body $Body
    $Global:GraphToken = $Response.access_token
    return $Global:GraphToken
}

function Invoke-GraphRequest {
    param([Parameter(Mandatory=$true)][String]$Uri)
    $Token = Get-GraphAccessToken
    $Headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }
    
    $AllItems = [System.Collections.Generic.List[Object]]::new()
    $CurrentUri = $Uri

    while ($CurrentUri) {
        $Response = Invoke-RestMethod -Uri $CurrentUri -Headers $Headers -Method Get
        if ($Response.value) {
            $AllItems.AddRange($Response.value)
        }
        else {
            $AllItems.Add($Response)
        }
        $CurrentUri = $Response.'@odata.nextLink'
    }
    return $AllItems
}

# -----------------------------------------------------------------------------
# 4. INVENTORY SYNC ENGINE
# -----------------------------------------------------------------------------
function Start-InventorySync {
    $SyncId = [Guid]::NewGuid().ToString()
    $StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Log "Starting Inventory Sync Job [$SyncId]..." "INFO"

    Invoke-SQLiteQuery -Query "INSERT INTO SyncHistory (SyncId, Started, Status) VALUES (@SyncId, @Started, 'IN_PROGRESS')" `
        -Parameters @{ SyncId = $SyncId; Started = $StartTime } -NonQuery

    try {
        $Now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Step 1: Managed Devices
        Write-Log "Querying /deviceManagement/managedDevices..." "INFO"
        $SelectFields = "id,azureADDeviceId,deviceName,userPrincipalName,managementAgent,ownerType,complianceState,deviceType,osVersion,lastSyncDateTime,deviceRegistrationState,managementState,exchangeAccessState,exchangeAccessStateReason,jailbroken,enrolledDateTime,deviceEnrollmentType,notes"
        $DevicesUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$select=$SelectFields"
        $Devices = Invoke-GraphRequest -Uri $DevicesUri

        Write-Log "Upserting $($Devices.Count) managed devices into SQLite..." "INFO"
        foreach ($Dev in $Devices) {
            $Query = @"
            INSERT INTO Devices (DeviceId, AzureADDeviceId, DeviceName, UserPrincipalName, ManagementAgent, OwnerType, ComplianceState, DeviceType, OSVersion, LastSyncDateTime, DeviceRegistrationState, ManagementState, ExchangeAccessState, ExchangeAccessStateReason, Jailbroken, EnrolledDateTime, DeviceEnrollmentType, Notes, FirstSeen, LastSeen)
            VALUES (@DeviceId, @AzureADDeviceId, @DeviceName, @UserPrincipalName, @ManagementAgent, @OwnerType, @ComplianceState, @DeviceType, @OSVersion, @LastSyncDateTime, @DeviceRegistrationState, @ManagementState, @ExchangeAccessState, @ExchangeAccessStateReason, @Jailbroken, @EnrolledDateTime, @DeviceEnrollmentType, @Notes, @Now, @Now)
            ON CONFLICT(DeviceId) DO UPDATE SET
                AzureADDeviceId=excluded.AzureADDeviceId, DeviceName=excluded.DeviceName, UserPrincipalName=excluded.UserPrincipalName, OSVersion=excluded.OSVersion, LastSyncDateTime=excluded.LastSyncDateTime, ComplianceState=excluded.ComplianceState, LastSeen=excluded.LastSeen;
"@
            $Params = @{
                DeviceId = $Dev.id; AzureADDeviceId = $Dev.azureADDeviceId; DeviceName = $Dev.deviceName
                UserPrincipalName = $Dev.userPrincipalName; ManagementAgent = $Dev.managementAgent
                OwnerType = $Dev.ownerType; ComplianceState = $Dev.complianceState; DeviceType = $Dev.deviceType
                OSVersion = $Dev.osVersion; LastSyncDateTime = $Dev.lastSyncDateTime
                DeviceRegistrationState = $Dev.deviceRegistrationState; ManagementState = $Dev.managementState
                ExchangeAccessState = $Dev.exchangeAccessState; ExchangeAccessStateReason = $Dev.exchangeAccessStateReason
                Jailbroken = [String]$Dev.jailbroken; EnrolledDateTime = $Dev.enrolledDateTime
                DeviceEnrollmentType = $Dev.deviceEnrollmentType; Notes = $Dev.notes; Now = $Now
            }
            Invoke-SQLiteQuery -Query $Query -Parameters $Params -NonQuery
        }

        # Step 2: Global Detected Apps
        Write-Log "Querying /deviceManagement/detectedApps..." "INFO"
        $AppsUri = "https://graph.microsoft.com/beta/deviceManagement/detectedApps"
        $Apps = Invoke-GraphRequest -Uri $AppsUri

        Write-Log "Upserting $($Apps.Count) detected applications..." "INFO"
        $RelCount = 0
        foreach ($App in $Apps) {
            $AppQuery = @"
            INSERT INTO Applications (AppId, DisplayName, Version, Publisher, Platform, SizeInBytes, DeviceCount, FirstSeen, LastSeen)
            VALUES (@AppId, @DisplayName, @Version, @Publisher, @Platform, @SizeInBytes, @DeviceCount, @Now, @Now)
            ON CONFLICT(AppId) DO UPDATE SET
                DisplayName=excluded.DisplayName, Version=excluded.Version, Publisher=excluded.Publisher, DeviceCount=excluded.DeviceCount, LastSeen=excluded.LastSeen;
"@
            $AppParams = @{
                AppId = $App.id; DisplayName = $App.displayName; Version = $App.version
                Publisher = $App.publisher; Platform = $App.platform; SizeInBytes = $App.sizeInBytes
                DeviceCount = $App.deviceCount; Now = $Now
            }
            Invoke-SQLiteQuery -Query $AppQuery -Parameters $AppParams -NonQuery

            # Step 3: Map App -> Devices
            if ($App.deviceCount -gt 0) {
                $MappedDevicesUri = "https://graph.microsoft.com/beta/deviceManagement/detectedApps/$($App.id)/managedDevices?`$select=id"
                try {
                    $MappedDevices = Invoke-GraphRequest -Uri $MappedDevicesUri
                    foreach ($mDev in $MappedDevices) {
                        $RelQuery = @"
                        INSERT INTO DeviceApplications (DeviceId, AppId, DetectedVersion, FirstSeen, LastSeen)
                        VALUES (@DeviceId, @AppId, @Version, @Now, @Now)
                        ON CONFLICT(DeviceId, AppId) DO UPDATE SET DetectedVersion=excluded.DetectedVersion, LastSeen=excluded.LastSeen;
"@
                        Invoke-SQLiteQuery -Query $RelQuery -Parameters @{ DeviceId = $mDev.id; AppId = $App.id; Version = $App.version; Now = $Now } -NonQuery
                        $RelCount++
                    }
                }
                catch {
                    Write-Log "Could not resolve devices for app $($App.displayName) ($($App.id)): $_" "WARN"
                }
            }
        }

        # Step 4: Reconcile Entra Groups
        Invoke-ReconcileEntraGroups

        $EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $HistoryUpdate = @"
        UPDATE SyncHistory SET Completed = @Completed, DeviceCount = @DeviceCount, ApplicationCount = @ApplicationCount, RelationshipCount = @RelCount, Status = 'SUCCESS'
        WHERE SyncId = @SyncId;
"@
        Invoke-SQLiteQuery -Query $HistoryUpdate -Parameters @{
            Completed = $EndTime; DeviceCount = $Devices.Count; ApplicationCount = $Apps.Count
            RelCount = $RelCount; SyncId = $SyncId
        } -NonQuery

        Write-Log "Sync Job [$SyncId] finished successfully. Devices: $($Devices.Count), Apps: $($Apps.Count), Links: $RelCount" "INFO"
    }
    catch {
        $ErrMsg = $_.ToString().Replace("'", "''")
        Write-Log "Sync Failure: $ErrMsg" "ERROR"
        Invoke-SQLiteQuery -Query "UPDATE SyncHistory SET Status = 'FAILED', ErrorMessage = '$ErrMsg' WHERE SyncId = '$SyncId'" -NonQuery
    }
}

# -----------------------------------------------------------------------------
# 5. ENTRA ID GROUP RECONCILIATION ENGINE
# -----------------------------------------------------------------------------
function Invoke-ReconcileEntraGroups {
    Write-Log "Starting Entra ID Managed Security Group Reconciliation..." "INFO"
    $Groups = Invoke-SQLiteQuery -Query "SELECT * FROM ManagedGroups WHERE Enabled = 1"

    foreach ($G in $Groups.Rows) {
        $GroupId = $G.GroupId
        $AppName = $G.AppName
        $TargetVersion = [Version]$G.AppVersion
        $Op = $G.ComparisonOperator

        Write-Log "Reconciling Group [$($G.GroupName)] ($GroupId) for App: $AppName Target: $TargetVersion Op: $Op" "INFO"

        # Query SQLite to compute Desired Entra Device Identifiers
        $DbDevices = Invoke-SQLiteQuery -Query @"
        SELECT d.AzureADDeviceId, da.DetectedVersion 
        FROM DeviceApplications da
        JOIN Devices d ON d.DeviceId = da.DeviceId
        JOIN Applications a ON a.AppId = da.AppId
        WHERE a.DisplayName = @AppName AND d.AzureADDeviceId IS NOT NULL AND d.AzureADDeviceId != ''
"@ -Parameters @{ AppName = $AppName }

        $DesiredEntraIds = [System.Collections.Generic.HashSet[String]]::new()
        foreach ($Row in $DbDevices.Rows) {
            $InstVersion = [Version]"0.0.0.0"
            [Version]::TryParse($Row.DetectedVersion, [ref]$InstVersion) | Out-Null
            
            $Match = $false
            switch ($Op) {
                "EQUALS"             { $Match = ($InstVersion -eq $TargetVersion) }
                "LESS_THAN"          { $Match = ($InstVersion -lt $TargetVersion) }
                "LESS_THAN_OR_EQUAL" { $Match = ($InstVersion -le $TargetVersion) }
            }
            if ($Match) { $DesiredEntraIds.Add($Row.AzureADDeviceId) | Out-Null }
        }

        # Fetch Current Entra Group Members
        $GroupMembersUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id,deviceId"
        $CurrentMembers = Invoke-GraphRequest -Uri $GroupMembersUri
        
        $CurrentMap = @{} # AzureADDeviceId -> DirectoryObjectId
        foreach ($Mem in $CurrentMembers) {
            if ($Mem.deviceId) { $CurrentMap[$Mem.deviceId] = $Mem.id }
        }

        # Calculate Diff
        $ToAdd = $DesiredEntraIds | Where-Object { -not $CurrentMap.ContainsKey($_) }
        $ToRemove = $CurrentMap.Keys | Where-Object { -not $DesiredEntraIds.Contains($_) }

        $Token = Get-GraphAccessToken
        $Headers = @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" }

        # Execute Additions
        foreach ($EntraDevId in $ToAdd) {
            # Need Directory Object ID for Entra Device Object
            $DevObj = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$EntraDevId'&`$select=id"
            if ($DevObj.Count -gt 0) {
                $DirectoryObjectId = $DevObj[0].id
                $AddUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref"
                $Body = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$DirectoryObjectId" } | ConvertTo-Json
                try {
                    Invoke-RestMethod -Uri $AddUri -Headers $Headers -Method Post -Body $Body | Out-Null
                    Write-Log "Added Device $EntraDevId to Group $GroupId" "INFO"
                } catch { Write-Log "Failed to add $EntraDevId: $_" "WARN" }
            }
        }

        # Execute Removals
        foreach ($EntraDevId in $ToRemove) {
            $DirectoryObjectId = $CurrentMap[$EntraDevId]
            $RemoveUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/$DirectoryObjectId/`$ref"
            try {
                Invoke-RestMethod -Uri $RemoveUri -Headers $Headers -Method Delete | Out-Null
                Write-Log "Removed Device $EntraDevId from Group $GroupId" "INFO"
            } catch { Write-Log "Failed to remove $EntraDevId: $_" "WARN" }
        }

        $SyncStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Invoke-SQLiteQuery -Query "UPDATE ManagedGroups SET LastSync = '$SyncStamp' WHERE GroupId = '$GroupId'" -NonQuery
    }
}

# -----------------------------------------------------------------------------
# 6. GRAPHICAL USER INTERFACE (WPF ENGINE)
# -----------------------------------------------------------------------------
function Start-InventoryGUI {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

    [XML]$Xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Intune Application Inventory &amp; Target Engine" Height="700" Width="1100"
        Background="#F3F4F6" WindowStartupLocation="CenterScreen">
    <Grid Margin="15">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Top Header & Search Bar -->
        <Border Grid.Row="0" Background="#FFFFFF" CornerRadius="8" Padding="15" Margin="0,0,0,15">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Orientation="Horizontal" Grid.Column="0">
                    <TextBlock Text="Search Applications:" VerticalAlignment="Center" FontWeight="Bold" Margin="0,0,10,0" Foreground="#374151"/>
                    <TextBox x:Name="TxtSearch" Width="300" Height="30" VerticalContentAlignment="Center" Padding="5,0"/>
                    <Button x:Name="BtnSearch" Content="🔍 Search" Width="90" Height="30" Margin="10,0,0,0" Background="#2563EB" Foreground="White" FontWeight="Bold"/>
                </StackPanel>
                <StackPanel Orientation="Horizontal" Grid.Column="1">
                    <Button x:Name="BtnSyncNow" Content="⚡ Sync Now" Width="110" Height="30" Background="#059669" Foreground="White" FontWeight="Bold" Margin="0,0,10,0"/>
                    <Button x:Name="BtnExport" Content="📥 Export CSV" Width="110" Height="30" Background="#4B5563" Foreground="White" FontWeight="Bold"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Main Data View Panel -->
        <Grid Grid.Row="1">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="5"/>
                <ColumnDefinition Width="5*"/>
            </Grid.ColumnDefinitions>

            <!-- Application List Panel -->
            <GroupBox Grid.Column="0" Header="Detected Applications" FontWeight="Bold" Foreground="#1F2937">
                <DataGrid x:Name="GridApps" AutoGenerateColumns="False" IsReadOnly="True" SelectionMode="Single"
                          GridLinesVisibility="Horizontal" HeadersVisibility="Column" Background="White" RowHeight="26">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="Application Name" Binding="{Binding DisplayName}" Width="*"/>
                        <DataGridTextColumn Header="Version" Binding="{Binding Version}" Width="110"/>
                        <DataGridTextColumn Header="Publisher" Binding="{Binding Publisher}" Width="120"/>
                        <DataGridTextColumn Header="Devices" Binding="{Binding DeviceCount}" Width="65"/>
                    </DataGrid.Columns>
                </DataGrid>
            </GroupBox>

            <GridSplitter Grid.Column="1" Width="5" HorizontalAlignment="Stretch" Background="#E5E7EB"/>

            <!-- Devices Panel -->
            <GroupBox Grid.Column="2" Header="Devices Running Selected Application" FontWeight="Bold" Foreground="#1F2937">
                <Grid>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    <DataGrid x:Name="GridDevices" Grid.Row="0" AutoGenerateColumns="False" IsReadOnly="True"
                              GridLinesVisibility="Horizontal" HeadersVisibility="Column" Background="White" RowHeight="26">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Device Name" Binding="{Binding DeviceName}" Width="*"/>
                            <DataGridTextColumn Header="User UPN" Binding="{Binding UserPrincipalName}" Width="*"/>
                            <DataGridTextColumn Header="OS Version" Binding="{Binding OSVersion}" Width="90"/>
                            <DataGridTextColumn Header="Detected Ver." Binding="{Binding DetectedVersion}" Width="90"/>
                        </DataGrid.Columns>
                    </DataGrid>
                    <StackPanel Grid.Row="1" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
                        <Button x:Name="BtnCreateGroup" Content="➕ Create Entra Upgrade Group" Height="32" Padding="15,0"
                                Background="#7C3AED" Foreground="White" FontWeight="Bold"/>
                    </StackPanel>
                </Grid>
            </GroupBox>
        </Grid>

        <!-- Footer Status Strip -->
        <Border Grid.Row="2" Background="#FFFFFF" CornerRadius="6" Padding="8" Margin="0,15,0,0">
            <TextBlock x:Name="TxtStatus" Text="Ready." Foreground="#6B7280" FontSize="11"/>
        </Border>
    </Grid>
</Window>
"@

    $Reader = (New-Object System.Xml.XmlNodeReader $Xaml)
    $Window = [System.Windows.Markup.XamlReader]::Load($Reader)

    # Bind Controls
    $TxtSearch     = $Window.FindName("TxtSearch")
    $BtnSearch     = $Window.FindName("BtnSearch")
    $BtnSyncNow    = $Window.FindName("BtnSyncNow")
    $BtnExport     = $Window.FindName("BtnExport")
    $GridApps      = $Window.FindName("GridApps")
    $GridDevices   = $Window.FindName("GridDevices")
    $BtnCreateGroup= $Window.FindName("BtnCreateGroup")
    $TxtStatus     = $Window.FindName("TxtStatus")

    # Load Applications Function
    $LoadApps = {
        param([String]$Filter = "")
        $Query = "SELECT AppId, DisplayName, Version, Publisher, DeviceCount FROM Applications"
        if (-not [String]::IsNullOrWhiteSpace($Filter)) {
            $Query += " WHERE DisplayName LIKE '%$($Filter.Replace("'", "''"))%' OR Publisher LIKE '%$($Filter.Replace("'", "''"))%'"
        }
        $Query += " ORDER BY DisplayName ASC LIMIT 500"
        $DT = Invoke-SQLiteQuery -Query $Query
        $GridApps.ItemsSource = $DT.DefaultView
        $TxtStatus.Text = "Loaded $($DT.Rows.Count) applications at $(Get-Date -Format 'HH:mm:ss')."
    }

    # Bind Events
    $BtnSearch.Add_Click({ &$LoadApps $TxtSearch.Text })
    
    $GridApps.Add_SelectionChanged({
        if ($GridApps.SelectedItem) {
            $SelectedRow = $GridApps.SelectedItem.Row
            $AppId = $SelectedRow["AppId"]
            $Query = @"
            SELECT d.DeviceName, d.UserPrincipalName, d.OSVersion, da.DetectedVersion
            FROM DeviceApplications da
            JOIN Devices d ON d.DeviceId = da.DeviceId
            WHERE da.AppId = '$AppId'
            ORDER BY d.DeviceName ASC
"@
            $DevDT = Invoke-SQLiteQuery -Query $Query
            $GridDevices.ItemsSource = $DevDT.DefaultView
        }
    })

    $BtnSyncNow.Add_Click({
        $BtnSyncNow.IsEnabled = $false
        $TxtStatus.Text = "Executing background sync... Please wait."
        
        # Simple Async Job Execution
        $ScriptBlock = {
            param($Path)
            & $Path -Sync
        }
        $PS = [PowerShell]::Create().AddScript($ScriptBlock).AddArgument($PSCommandPath)
        $AsyncResult = $PS.BeginInvoke()
        
        # Non-blocking poll timer
        $Timer = New-Object System.Windows.Threading.DispatcherTimer
        $Timer.Interval = [TimeSpan]::FromSeconds(2)
        $Timer.Add_Tick({
            if ($AsyncResult.IsCompleted) {
                $Timer.Stop()
                $PS.EndInvoke($AsyncResult)
                $PS.Dispose()
                $BtnSyncNow.IsEnabled = $true
                &$LoadApps $TxtSearch.Text
                [System.Windows.MessageBox]::Show("Inventory Sync Completed!", "Success", "OK", "Information")
            }
        })
        $Timer.Start()
    })

    $BtnCreateGroup.Add_Click({
        if (-not $GridApps.SelectedItem) {
            [System.Windows.MessageBox]::Show("Select an application first.", "Notice", "OK", "Warning")
            return
        }
        
        $AppRow = $GridApps.SelectedItem.Row
        $AppName = $AppRow["DisplayName"]
        $AppVer  = $AppRow["Version"]

        # Prompt for Entra Group Creation
        $GroupName = "INTUNE-UPGRADE-$($AppName -replace '[^a-zA-Z0-9]','').Trim()-$($AppVer -replace '[^a-zA-Z0-9]','')"
        $Confirm = [System.Windows.MessageBox]::Show("Create new static Entra Security Group and target rule?`n`nGroup Name: $GroupName`nApp: $AppName`nTarget Ver: < $AppVer", "Create Security Group", "YesNo", "Question")

        if ($Confirm -eq "Yes") {
            try {
                $Token = Get-GraphAccessToken
                $Headers = @{ "Authorization" = "Bearer $Token"; "Content-Type" = "application/json" }
                
                # Step 1: Create Group in Entra ID
                $GroupBody = @{
                    displayName     = $GroupName
                    description     = "Auto-managed group for devices needing $AppName upgrade to $AppVer"
                    securityEnabled = $true
                    mailEnabled     = $false
                    mailNickname    = "intune-app-" + [Guid]::NewGuid().ToString().Substring(0,8)
                } | ConvertTo-Json

                $NewGroup = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups" -Headers $Headers -Method Post -Body $GroupBody
                
                # Step 2: Save to ManagedGroups Database Table
                $InsertGroup = @"
                INSERT INTO ManagedGroups (GroupId, GroupName, AppId, AppName, AppVersion, ComparisonOperator, Enabled)
                VALUES (@GroupId, @GroupName, @AppId, @AppName, @AppVersion, 'LESS_THAN', 1)
"@
                Invoke-SQLiteQuery -Query $InsertGroup -Parameters @{
                    GroupId = $NewGroup.id; GroupName = $GroupName; AppId = $AppRow["AppId"]
                    AppName = $AppName; AppVersion = $AppVer
                } -NonQuery

                [System.Windows.MessageBox]::Show("Group created successfully! ID: $($NewGroup.id)`nReconciliation will occur on the next sync.", "Success", "OK", "Information")
            }
            catch {
                [System.Windows.MessageBox]::Show("Error creating Entra group: $_", "Error", "OK", "Error")
            }
        }
    })

    $BtnExport.Add_Click({
        if ($GridApps.ItemsSource) {
            $SaveFileDialog = New-Object Microsoft.Win32.SaveFileDialog
            $SaveFileDialog.Filter = "CSV File (*.csv)|*.csv"
            $SaveFileDialog.FileName = "IntuneInventoryExport.csv"
            if ($SaveFileDialog.ShowDialog() -eq $true) {
                $GridApps.ItemsSource.Table | Export-Csv -Path $SaveFileDialog.FileName -NoTypeInformation
                [System.Windows.MessageBox]::Show("Export completed!", "Success", "OK", "Information")
            }
        }
    })

    # Initial Load
    &$LoadApps
    $Window.ShowDialog() | Out-Null
}

# -----------------------------------------------------------------------------
# 7. EXECUTION ENTRY POINT
# -----------------------------------------------------------------------------
if ($Sync) {
    Start-InventorySync
}
elseif ($Gui) {
    Start-InventoryGUI
}
else {
    Write-Host "Intune Inventory System Utility" -ForegroundColor Cyan
    Write-Host "----------------------------------"
    Write-Host "Usage:"
    Write-Host "  .\IntuneInventory.ps1 -Gui   : Launch UI Console"
    Write-Host "  .\IntuneInventory.ps1 -Sync  : Run Scheduled Inventory Sync Task"
}