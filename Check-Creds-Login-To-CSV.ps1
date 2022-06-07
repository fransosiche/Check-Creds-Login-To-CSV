<#
    .SYNOPSIS
        Get-Eventlog 4624 and 4625 (Sucess/fail local/rdp login attempts) to parse them in CSV
    .DESCRIPTION
        This script aim to gives visibility on users credentials used on a specific perimeter
    .PARAMETER -DCNAME & -TIMESTAMP (no mandatory, default 1)
        -DCNAME <all> OR <specific name like AD01>
    .EXAMPLE
        Check-Creds-Login-To-CSV.ps1 -DCNAME AD01 -TIMESTAMP 2

        Description
        -----------
        This command will get every event security (login) log present on AD01 from 2 day and parse them to a CSV
    .NOTES
        Created by      : François Biron
        Date Coded      : 07/06/2022
#>

#getting needed parameters
param (
    [string]$DCName = $( throw "-DCName is required, <all> or <specific name> like <AD01>" ),
    [int]$Timestamp
)

#If we're not getting DCName, throw and exit
if (-not($DCName))
{
    Throw “-DCName is required, <all> or <specific name> like <AD01>”
}

#If no timestamp is specified, default is 1
if (-not($Timestamp))
{
    $Timestamp = 1;
}

#If DCName param is all, get all domain controller
if ($DCName -eq "all" -or $DCName -eq "All")
{
    # Find DC list from Active Directory
    $DCs = Get-ADDomainController -Filter *
}
#Else go trough only the specific one
else
{
    $DCs = Get-ADDomainController -Filter { Name -like $DCName }
}

#If DCs is empty, it means DC param doesnt exit, so throw error
if (-not($DCs))
{
    throw "Can't find DC"
}

# Define time for report (default is 1 day)
$Start_Date = (get-date).AddDays(-$Timestamp)

#Create datable with Columns to store data
$Result_Table = New-Object System.Data.Datatable
[void]$Result_Table.Columns.Add("Username")
[void]$Result_Table.Columns.Add("Type")
[void]$Result_Table.Columns.Add("Status")
[void]$Result_Table.Columns.Add("Workstation")
[void]$Result_Table.Columns.Add("IP Address")

# Store successful logon events from security logs with the specified dates and workstation/IP in an array
foreach ($DC in $DCs)
{
    write-host "Loading all security events from each DC plz wait......."
    $slogonevents = Get-Eventlog -LogName Security -ComputerName $DC.Hostname -after $Start_Date | where { ($_.eventID -eq 4624) -or ($_.eventID -eq 4625) }
}

# Crawl through events; print all logon history with type, date/time, status, account name, computer and IP address if user logged on remotely
write-host "Going through all security events logs  and parsing them....plz wait......."
foreach ($e in $slogonevents)
{
    # Logon Successful Events
    # Local (Logon Type 2)
    if (($e.EventID -eq 4624) -and ($e.ReplacementStrings[8] -eq 10))
    {
        if (-not( $Result_Table.Where({ $_.Username -match $e.ReplacementStrings[5] })))
        {
            [void]$Result_Table.Rows.Add($e.ReplacementStrings[5], "Remote Logon", "Success", $e.ReplacementStrings[11], $e.ReplacementStrings[18])
        }
    }
    # Logon Successful Events
    # Local (Logon Type 2)
    if (($e.EventID -eq 4624) -and ($e.ReplacementStrings[8] -eq 2))
    {
        if (-not( $Result_Table.Where({ $_.Username -match $e.ReplacementStrings[5] })))
        {
            [void]$Result_Table.Rows.Add($e.ReplacementStrings[5], "Local Logon", "Success", $e.ReplacementStrings[11], "none")
        }
    }
    # Logon Failed Events
    # Local (Logon Type 2)
    if (($e.EventID -eq 4625) -and ($e.ReplacementStrings[8] -eq 2))
    {
        if (-not( $Result_Table.Where({ $_.Username -match $e.ReplacementStrings[5] })))
        {
            [void]$Result_Table.Rows.Add($e.ReplacementStrings[5], "Local Logon", "Failed", $e.ReplacementStrings[11], "none")
        }
    }
    # Remote (Logon Type 10)
    if (($e.EventID -eq 4625) -and ($e.ReplacementStrings[8] -eq 10))
    {
        if (-not( $Result_Table.Where({ $_.Username -match $e.ReplacementStrings[5] })))
        {
            [void]$Result_Table.Rows.Add($e.ReplacementStrings[5], "Remote Logon", "Failed", $e.ReplacementStrings[11], $e.ReplacementStrings[18])
        }
    }
}

function Export-Table-To-CSV($Result_Table)
{
    Write-Host "Going to write result in CSV..."
    $Result_Table | Export-CSV -Path .\Auth_User_$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss') ).csv -Delimiter ';'
    Write-Host "CSV Auth_User_$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss') ).csv exported with success (csv is located at the same path as this script) !"
}

Export-Table-To-CSV($Result_Table)