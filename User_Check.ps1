# Find DC list from Active Directory 
$DCs = Get-ADDomainController -Filter *

# Define time for report (default is 1 day)
$startDate = (get-date).AddDays(-1)

$Result_Table = New-Object System.Data.Datatable

[void]$Result_Table.Columns.Add("Username")
[void]$Result_Table.Columns.Add("Type")
[void]$Result_Table.Columns.Add("Status")
[void]$Result_Table.Columns.Add("Workstation")
[void]$Result_Table.Columns.Add("IP Address")



# Store successful logon events from security logs with the specified dates and workstation/IP in an array
foreach ($DC in $DCs)
{
    write-host "Loading all Security event log plz wait......."
    $slogonevents = Get-Eventlog -LogName Security -ComputerName $DC.Hostname -after $startDate | where { ($_.eventID -eq 4624) -or ($_.eventID -eq 4625) }
}

# Crawl through events; print all logon history with type, date/time, status, account name, computer and IP address if user logged on remotely
write-host "Going throught all auth event log plz wait......."
foreach ($e in $slogonevents)
{

    # Logon Successful Events
    # Local (Logon Type 2)
    if (($e.EventID -eq 4624) -and ($e.ReplacementStrings[8] -eq 10))
    {

        if (( $Result_Table.Where({ $_.Username -match $e.ReplacementStrings[5] })))
        {
            write-host $e.ReplacementStrings[5] " already exist in record !"
        }
        else
        {

            [void]$Result_Table.Rows.Add($e.ReplacementStrings[5], "Remote Logon", "Success", $e.ReplacementStrings[11], $e.ReplacementStrings[18])
        }
    }

    # Logon Successful Events
    # Local (Logon Type 2)
    if (($e.EventID -eq 4624) -and ($e.ReplacementStrings[8] -eq 2))
    {
        if (( $Result_Table.Where({ $_.Username -match $e.ReplacementStrings[5] })))
        {
            write-host $e.ReplacementStrings[5] " already exist in record !"
        }
        else
        {
            [void]$Result_Table.Rows.Add($e.ReplacementStrings[5], "Local Logon", "Success", $e.ReplacementStrings[11], "none")
        }
    }

    # Logon Failed Events
    # Local (Logon Type 2)
    if (($e.EventID -eq 4625) -and ($e.ReplacementStrings[8] -eq 2))
    {
        if (( $Result_Table.Where({ $_.Username -match $e.ReplacementStrings[5] })))
        {
            write-host $e.ReplacementStrings[5] " already exist in record !"
        }
        else
        {
            [void]$Result_Table.Rows.Add($e.ReplacementStrings[5], "Local Logon", "Failed", $e.ReplacementStrings[11], "none")
        }

    }
    # Remote (Logon Type 10)
    if (($e.EventID -eq 4625) -and ($e.ReplacementStrings[8] -eq 10))
    {
        if (( $Result_Table.Where({ $_.Username -match $e.ReplacementStrings[5] })))
        {
            write-host $e.ReplacementStrings[5] " already exist in record !"
        }
        else
        {
            [void]$Result_Table.Rows.Add($e.ReplacementStrings[5], "Remote Logon", "Failed", $e.ReplacementStrings[11], $e.ReplacementStrings[18])
        }
    }

}

write-host "Going to write result in CSV"
$Result_Table | Export-CSV -Path .\Auth_User.csv -Delimiter ';'