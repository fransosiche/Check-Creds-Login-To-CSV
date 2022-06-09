<h1 align="center">
  Check-Creds-Login-To-CSV
  <br>
</h1>

### Main Features

Little script to Get-Eventlog 4624 and 4625 (Sucess/fail & local/rdp/batch/network... (using NTLMV1 or V2 or Kerberos protocols) logon attempts) to parse them in a CSV file

### Prerequisite

You have to enable policies to collect 4624 and 4625 logons and apply the policy to concerned OU :

Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies 

a.	System > Audit Security State Change —  “Success”.

b.	Logon/Logoff — Put "Audit Logon” and “Audit Logoff” to “Success” and “Failure”.

c.	Logon/Logoff > Audit — Put “Other Logon/Logoff Events” to “Success” and “Failure.”

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

### Output

![image](https://user-images.githubusercontent.com/33124690/172855703-9076b2ce-b037-4a2d-8728-af824d091c95.png)

### TODO
- Try catch
- Var type
