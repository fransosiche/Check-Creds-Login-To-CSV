<#
    .SYNOPSIS
        Get-Eventlog 4624 and 4625 (Sucess/fail local/rdp/batch/network (using NTLM v1 or V2 or Kerberos protocols) logon attempts) to parse them in a CSV file
    .DESCRIPTION
        This script aims to give visibility on users credentials present on a specific perimeter
    .PARAMETER -DCNAME & -TIMESTAMP (no mandatory, default 1)
        -DCNAME <all> OR <specific name like AD01>
    .EXAMPLE
        Invoke-Check-Cred -DCNAME AD01 -TIMESTAMP 2

        Description
        -----------
        This script will get every event security logons present on AD01 from 2 day and parse them to a CSV
    .NOTES
        Created by      : François Biron
        Date Coded      : 09/06/2022
#>

#Global variables
$Global:DCName;
$Global:Timestamp;
$Global:StartDate;
$Global:DCs;
$Global:Result_Table = New-Object System.Data.Datatable;
#Strings
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

#Function to store logons into datatable
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

    # If event id is sucessfull
    if (($e.EventID -eq $eventIDsucess) -and ($e.ReplacementStrings[8] -eq $logontype))
    {
        # Checking If event is not already present in the datatable to avoid redondancy
        if (-not($Result_Table.Where({ $_.Username -like $e.ReplacementStrings[5] -and $_.Type -like $Logontext -and ($_.Protocol -like $e.ReplacementStrings[10] -or $_.Protocol -like $e.ReplacementStrings[14]) })))
        {
            # Checking if the protocol used is NTLM V2 because Kerberos and NTLM are not in the same place [14] vs [10]
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
    # Same stuff for fail event
    if (($e.EventID -eq $eventIDfail) -and ($e.ReplacementStrings[8] -eq $logontype))
    {
        if (-not($Result_Table.Where({ $_.Username -like $e.ReplacementStrings[5] -and $_.Type -like $Logontext -and ($_.Protocol -like $e.ReplacementStrings[10] -or $_.Protocol -like $e.ReplacementStrings[14]) })))
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

# Export Datatable to CSV
function Export-Table-To-CSV
{
    Param(
        $Result_Table
    )
    Write-Info "Going to write result in CSV..."
    $Result_Table | Export-CSV -Path .\Auth_User_$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss') ).csv -Delimiter ';'
    Write-Good "CSV Auth_User_$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss') ).csv exported with success (csv is located at the same path as this script) !"
    Write-Good "Have a good day :)"
}

# Getting timestamp, checking if it's present and storing it as a datetime for later
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

# Getting DCName, checking if the param is ok and storing it for later
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

# Getting all the log from the DC(s) and crawling through events
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

    # Store logon events from security logs with the specified dates and workstation/IP in an array
    foreach ($DC in $DCs)
    {
        $slogonevents = Get-Eventlog -LogName Security -ComputerName $DC.Hostname -after $Start_Date | Where-Object { ($_.eventID -eq 4624) -or ($_.eventID -eq 4625) }
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

# Main function that call all other one
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