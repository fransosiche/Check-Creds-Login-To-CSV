<h1 align="center">
  Check-Creds-Login-To-CSV
  <br>
</h1>

### Main Features

Get-Eventlog 4624 and 4625 (Sucess/fail & local/rdp/batch/network... (using NTLM v1 or V2 or Kerberos protocols) logon attempts) to parse them in a CSV file

### Prerequisite

You have to enable policy to collect 4624 and 4625 logons and apply the policy to concerned OU :

Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies 

a.	System > Audit Security State Change — Passez le à “Success”.
b.	Logon/Logoff — Mettez “Audit Logon” et “Audit Logoff” à “Success” et “Failure”.
c.	Logon/Logoff > Audit — Mettez “Other Logon/Logoff Events” à “Success” et “Failure.”

### Example
```powershell
# To download and run the scripts for all DC
IEX((new-object net.webclient).downloadstring("https://raw.githubusercontent.com/fransosiche/Check-Creds-Login-To-CSV/main/Check-Creds-Login-To-CSV.ps1"));
Invoke-Check-Cred -DCName all

# You can change the timestamp, by default it's 1 day
Invoke-Check-Cred -DCName all -Timestamp 2

# You can specify only one DC (or multiple like "AD01, AD02", I didn't test that tho)
Invoke-Check-Cred -DCName AD01
```

### TODO
- Try catch
- Var type
