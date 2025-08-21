<#
.SYNOPSIS
    DomainSweep – Read-only Active Directory hygiene auditor.

.DESCRIPTION
    Performs a variety of hygiene checks in an Active Directory environment.
    Outputs findings in color-coded tables directly to the console.
    Safe to run; does not modify accounts or AD objects.

.EXAMPLE
    .\DomainSweep.ps1
    # Runs the audit and displays results in the console.

.NOTES
    Author: Ky
    Version: 1.0
#>

# ===============================================================
# PARAMETERS
# ===============================================================
param(
    [switch]$h  # Help flag
)


# ===============================================================
# ASCII Banner
# ===============================================================
$banner = @"
 _______   ______   .___  ___.      ___       __  .__   __.      _______.____    __    ____  _______  _______ .______
|       \ /  __  \  |   \/   |     /   \     |  | |  \ |  |     /       |\   \  /  \  /   / |   ____||   ____||   _  \
|  .--.  |  |  |  | |  \  /  |    /  ^  \    |  | |   \|  |    |   (----. \   \/    \/   /  |  |__   |  |__   |  |_)  |
|  |  |  |  |  |  | |  |\/|  |   /  /_\  \   |  | |  .    |     \   \      \            /   |   __|  |   __|  |   ___/
|  '--'  |  '--'  | |  |  |  |  /  _____  \  |  | |  |\   | .----)   |      \    /\    /    |  |____ |  |____ |  |
|_______/ \______/  |__|  |__| /__/     \__\ |__| |__| \__| |_______/        \__/  \__/     |_______||_______|| _|
"@

Write-Host $banner -ForegroundColor Blue
Write-Host "`n[*] Starting DomainSweep…`n" -ForegroundColor Green

# ===============================================================
# Help Feature
# ===============================================================
if ($h) {
    Write-Host @"
DomainSweep – Active Directory Hygiene Audit Tool
-------------------------------------------------

Usage:
    .\DomainSweep.ps1 [options]

Options:
    ->, -Output File	 Outputs results to output file .txt
    -h, -Help            Show this help message.

Examples:
    # Console output only
    .\DomainSweep.ps1 > example.txt

"@ -ForegroundColor White
    exit
}

# ===============================================================
# Helper function for colored output
# ===============================================================
function Write-Finding {
    param(
        [string]$Message,
        [string]$Severity = "Info"  # Info, Warning, Critical
    )
    
    switch ($Severity) {
        "Info"     { $color = "White" }
        "Warning"  { $color = "Yellow" }
        "Critical" { $color = "Red" }
        default    { $color = "White" }
    }
    
    Write-Host $Message -ForegroundColor $color
}

# ===============================================================
# ACCOUNT HYGIENE
# ===============================================================
Write-Finding "[*] Checking account hygiene..." "Info"

$staleCutoff = (Get-Date).AddDays(-90)
$staleUsers = Get-ADUser -Filter * -Properties LastLogonDate |
    Where-Object { $_.Enabled -and $_.LastLogonDate -lt $staleCutoff } |
    Select SamAccountName

$pwdNeverExpire = Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=65536)" |
    Select SamAccountName

$pwdNotRequired = Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=32)" |
    Select SamAccountName

if ($staleUsers) { $staleUsers | Format-Table -AutoSize } else { Write-Finding "Stale_Users -> No findings" "Info" }
if ($pwdNeverExpire) { Write-Finding "=== PwdNeverExpires ($($pwdNeverExpire.Count) entries) ===" "Warning"; $pwdNeverExpire | Format-Table -AutoSize } else { Write-Finding "PwdNeverExpires -> No findings" "Info" }
if ($pwdNotRequired) { $pwdNotRequired | Format-Table -AutoSize } else { Write-Finding "PwdNotRequired -> No findings" "Info" }

# ===============================================================
# KERBEROS RISKS
# ===============================================================
Write-Finding "`n[*] Checking Kerberos risks..." "Info"

$asrepUsers = Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" -Properties userPrincipalName |
    Select SamAccountName, userPrincipalName

$weakSPNs = Get-ADUser -LDAPFilter "(&(objectClass=user)(servicePrincipalName=*))" -Properties servicePrincipalName |
    Select SamAccountName, servicePrincipalName

if ($asrepUsers) { $asrepUsers | Format-Table -AutoSize } else { Write-Finding "ASREP_NoPreauth -> No findings" "Info" }
if ($weakSPNs) { Write-Finding "=== SPNs_WeakEncryption ($($weakSPNs.Count) entries) ===" "Warning"; $weakSPNs | Format-Table -AutoSize } else { Write-Finding "SPNs_WeakEncryption -> No findings" "Info" }

# ===============================================================
# DELEGATION ISSUES
# ===============================================================
Write-Finding "`n[*] Checking delegation issues..." "Info"

$unconstrained = Get-ADComputer -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" -Properties dNSHostName |
    Select dNSHostName

$constrainedAnyProtocol = Get-ADComputer -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation |
    Select Name, msDS-AllowedToDelegateTo, TrustedToAuthForDelegation |
    Where-Object { $_.TrustedToAuthForDelegation -eq $true }

if ($unconstrained) { Write-Finding "=== Delegation_Unconstrained ($($constrainedAnyProtocol.Count) entries) ===" "Critical"; $unconstrained | Format-Table -AutoSize } else { Write-Finding "Delegation_Unconstrained -> No findings" "Info" }
if ($constrainedAnyProtocol) { $constrainedAnyProtocol | Format-Table -AutoSize } else { Write-Finding "Delegation_AnyProtocol -> No findings" "Info" }

# ===============================================================
# SHADOW ADMINS / ACL RISKS
# ===============================================================
Write-Finding "`n[*] Checking for potential shadow admins (risky ACLs)..." "Info"

$domainDN = (Get-ADDomain).DistinguishedName
$criticalOUs = @("CN=Users,$domainDN","OU=Domain Controllers,$domainDN")

$aclFindings = foreach ($ou in $criticalOUs) {
    $acl = Get-Acl "AD:$ou"
    foreach ($ace in $acl.Access) {
        if ($ace.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner") {
            [PSCustomObject]@{
                OU = $ou
                Identity = $ace.IdentityReference
                Rights = $ace.ActiveDirectoryRights
            }
        }
    }
}

if ($aclFindings) { Write-Finding "=== ACL_RiskyPermissions ($($aclFindings.Count) entries) ===" "Critical"; $aclFindings | Format-Table -AutoSize } else { Write-Finding "ACL_RiskyPermissions -> No findings" "Info" }

# ===============================================================
# SYSVOL / GPO RISKS
# ===============================================================
Write-Finding "`n[*] Checking SYSVOL for writable scripts..." "Info"

$share = "\\$((Get-ADDomainController -Discover).HostName)\SYSVOL"
$sysvolFindings = Get-ChildItem "$share\*\Policies" -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object {
        $acl = Get-Acl $_.FullName
        foreach ($ace in $acl.Access) {
            if ($ace.FileSystemRights.ToString().Contains("Write") -and
                $ace.IdentityReference -notmatch "Administrators|SYSTEM|Domain Admins") {
                [PSCustomObject]@{
                    Path = $_.FullName
                    Identity = $ace.IdentityReference
                    Rights = $ace.FileSystemRights
                }
            }
        }
    }

if ($sysvolFindings) { Write-Finding "=== SYSVOL_Writable ($($sysvolFindings.Count) entries) ===" "Critical"; $sysvolFindings | Format-Table -AutoSize } else { Write-Finding "SYSVOL_Writable -> No findings" "Info" }

# ===============================================================
# LAPS / GPP CHECK
# ===============================================================
Write-Finding "`n[*] Checking LAPS coverage..." "Info"
try {
    $allComputers = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime
    $lapsCutoff = (Get-Date).AddDays(-60)
    $lapsRecent = $allComputers | Where-Object {
        $_.'ms-Mcs-AdmPwdExpirationTime' -and
        ([DateTime]::FromFileTimeUtc([int64]$_.'ms-Mcs-AdmPwdExpirationTime') -gt $lapsCutoff)
    }
    if ($lapsRecent) { Write-Finding "LAPS_Compliant ($($lapsRecent.Count)/$($allComputers.Count) computers)" "Info" } else { Write-Finding "LAPS not deployed or no recent passwords" "Info" }
}
catch {
    Write-Finding "LAPS not deployed (skipping check)" "Info"
}

# ===============================================================
# SUMMARY TABLE
# ===============================================================
$summary = [PSCustomObject]@{
    Section = "PwdNeverExpires"; Count = ($pwdNeverExpire | Measure-Object).Count
}, [PSCustomObject]@{
    Section = "SPNs_WeakEncryption"; Count = ($weakSPNs | Measure-Object).Count
}, [PSCustomObject]@{
    Section = "Delegation_Unconstrained"; Count = ($unconstrained | Measure-Object).Count
}, [PSCustomObject]@{
    Section = "ACL_RiskyPermissions"; Count = ($aclFindings | Measure-Object).Count
}, [PSCustomObject]@{
    Section = "SYSVOL_Writable"; Count = ($sysvolFindings | Measure-Object).Count
}

Write-Finding "`n[*] === DomainSweep Summary ===" "Info"
$summary | Format-Table -AutoSize

Write-Finding "`n[*] Audit complete!" "Info"