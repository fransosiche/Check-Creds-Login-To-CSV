<#
    .SYNOPSIS
        Get Win-event 4624 and 4625 (Sucess/fail local/rdp login attempts) to parse them in CSV
    .DESCRIPTION
        This script aim to give visibility on users credentials present on machines
    .PARAMETER -DCNAME & -TIMESTAMP (no mandatory, default 1)
        -DCNAME <all> OR <specific name like AD01>
    .EXAMPLE
        User-Check.ps1 -DCNAME AD01 -TIMESTAMP 2

        Description
        -----------
        This command will get every event security (login) log present on AD01 from 2 day and parse them to a CSV fail
    .NOTES
        Created by      : François Biron
        Date Coded      : 07/06/2022
    .LINK

#>
