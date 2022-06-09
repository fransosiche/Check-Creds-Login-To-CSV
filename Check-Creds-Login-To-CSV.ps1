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

$Global:DCName;
$Global:Timestamp;
$Global:StartDate;
$Global:DCs;
$Global:Result_Table = New-Object System.Data.Datatable;
$Global:Spacing = "`t"
$Global:PlusLine = "`t[+]"
$Global:ErrorLine = "`t[-]"
$Global:InfoLine = "`t[*]"

function Write-Good
{
    param($String) Write-Host $Global:PlusLine  $String -ForegroundColor 'Green'
}
function Write-Bad
{
    param($String) Write-Host $Global:ErrorLine $String -ForegroundColor 'red'
}
function Write-Info
{
    param($String) Write-Host $Global:InfoLine $String -ForegroundColor 'gray'
}
function ShowBanner
{
    $banner = @()
    $banner += $Global:Spacing + ''
    $banner += $Global:Spacing + 'By @Fransosiche'
    $banner += $Global:Spacing + ''
    $banner | foreach-object {
        Write-Host $_ -ForegroundColor (Get-Random -Input @('Green', 'Cyan', 'Yellow', 'gray', 'white'))
    }
}


function Store_Logon
{
    Param(
        $Result_Table,
        [array]$e,
        [int]$eventIDsucess,
        [int]$eventIDfail,
        [int]$logontype,
        [string]$Logontext
    )

    # Logon Successful Events
    if (($e.EventID -eq $eventIDsucess) -and ($e.ReplacementStrings[8] -eq $logontype))
    {
        if (-not( $Result_Table.Where({ $_.Username -like $e.ReplacementStrings[5] })))
        {
            if ($e.ReplacementStrings[14] -eq 'NTLM V2')
            {
                [void]$Result_Table.Rows.Add($e.ReplacementStrings[5], $Logontext, "Success", $e.ReplacementStrings[11], $e.ReplacementStrings[18], $e.ReplacementStrings[14])
            }
            else
            {
                [void]$Result_Table.Rows.Add($e.ReplacementStrings[5], $Logontext, "Success", $e.ReplacementStrings[11], $e.ReplacementStrings[18], $e.ReplacementStrings[10])
            }
        }
    }

    if (($e.EventID -eq $eventIDfail) -and ($e.ReplacementStrings[8] -eq $logontype))
    {
        if (-not( $Result_Table.Where({ $_.Username -like $e.ReplacementStrings[5] })))
        {
            if ($e.ReplacementStrings[14] -eq 'NTLM V2')
            {
                [void]$Result_Table.Rows.Add($e.ReplacementStrings[5], $Logontext, "Failed", $e.ReplacementStrings[11], $e.ReplacementStrings[18], $e.ReplacementStrings[14])
            }
            else
            {
                [void]$Result_Table.Rows.Add($e.ReplacementStrings[5], $Logontext, "Failed", $e.ReplacementStrings[11], $e.ReplacementStrings[18], $e.ReplacementStrings[10])
            }
        }
    }
    $Global:Result_Table = $Result_Table
}

#Export Datatable to CSV
function Export-Table-To-CSV
{
    Param(
        $Result_Table
    )
    Write-Info "Going to write result in CSV..."
    $Result_Table | Export-CSV -Path .\Auth_User_$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss') ).csv -Delimiter ';'
    Write-Good "CSV Auth_User_$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss') ).csv exported with success (csv is located at the same path as this script) !"
}

function Get-Timestamp
{
    Param(
        [int]$Timestamp
    )
    #If no timestamp is specified, default is 1
    if (-not($Timestamp))
    {
        $Timestamp = 1;
    }
    # Define time for report (default is 1 day)
    $Global:StartDate = (get-date).AddDays(-$Timestamp)
}

function Get-DC
{
    Param(
        $DCName
    )
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
    $Global:DCs = $DCs;

}

function Get-and-store-logs
{
    Param(
        [array]$Dcs,
        [DateTime] $Start_Date
    )
    #Create datable with Columns to store data
    [void]$Result_Table.Columns.Add("Username")
    [void]$Result_Table.Columns.Add("Type")
    [void]$Result_Table.Columns.Add("Status")
    [void]$Result_Table.Columns.Add("Workstation")
    [void]$Result_Table.Columns.Add("IP Address")
    [void]$Result_Table.Columns.Add("Protocol")

    # Store successful logon events from security logs with the specified dates and workstation/IP in an array
    foreach ($DC in $DCs)
    {
        $slogonevents = Get-Eventlog -LogName Security -ComputerName $DC.Hostname -after $Start_Date | where { ($_.eventID -eq 4624) -or ($_.eventID -eq 4625) }
    }
    $TotalItems = $slogonevents.Count
    $CurrentItem = 0
    $PercentComplete = 0
    # Crawl through events; print all logon history with type, date/time, status, account name, computer and IP address if user logged on remotely
    foreach ($e in $slogonevents)
    {
        Write-Progress -Activity "Checking Security Logon Events" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete
        Store_Logon -e $e -eventIDsucess 4624 -eventIDfail 4625 -logontype 2 -Result_Table $Result_Table -Logontext "Interactive Logon"
        Store_Logon -e $e -eventIDsucess 4624 -eventIDfail 4625 -logontype 3 -Result_Table $Result_Table -Logontext "Network Logon"
        Store_Logon -e $e -eventIDsucess 4624 -eventIDfail 4625 -logontype 4 -Result_Table $Result_Table -Logontext "Batch Logon"
        Store_Logon -e $e -eventIDsucess 4624 -eventIDfail 4625 -logontype 5 -Result_Table $Result_Table -Logontext "Service Logon"
        Store_Logon -e $e -eventIDsucess 4624 -eventIDfail 4625 -logontype 7 -Result_Table $Result_Table -Logontext "Unlock Logon"
        Store_Logon -e $e -eventIDsucess 4624 -eventIDfail 4625 -logontype 8 -Result_Table $Result_Table -Logontext "NetworkClearText Logon"
        Store_Logon -e $e -eventIDsucess 4624 -eventIDfail 4625 -logontype 9 -Result_Table $Result_Table -Logontext "NewCredentials Logon"
        Store_Logon -e $e -eventIDsucess 4624 -eventIDfail 4625 -logontype 10 -Result_Table $Result_Table -Logontext "Remote Interactive Logon"
        Store_Logon -e $e -eventIDsucess 4624 -eventIDfail 4625 -logontype 11 -Result_Table $Result_Table -Logontext "Cache Interactive Logon"
        $CurrentItem++
        $PercentComplete = [int](($CurrentItem / $TotalItems) * 100)
    }
    $Global:Result_Table = $Result_Table;
}
function Invoke-Check-Cred
{
    #getting needed parameters
    param (
        [string]$DCName = $( throw "-DCName is required, <all> or <specific name> like <AD01>" ),
        [int]$Timestamp
    )
    ShowBanner
    $Global:DCName = $DCName
    $Global:Timestamp = $Timestamp
    Get-Timestamp -Timestamp $Timestamp
    Write-Info "Getting timestamp and DCs..."
    Get-DC -DCName $DCName
    Write-Info "Going through all security events logs..."
    Get-and-store-logs -Dcs $Global:DCs -Start_Date $Global:StartDate
    Write-Good "Storing in datatable is done !"
    Export-Table-To-CSV -Result_Table $Global:Result_Table
}