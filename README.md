<h1 align="center">
  Check-Creds-Login-To-CSV
  <br>
</h1>

### Main Features

Little script to Get-Eventlog 4624 and 4625 (Sucess/fail) and then parse them into a CSV file. This script aims to give visibility on authentification secrets presents on a specific perimeter.

It collects the different logon types such as : 
- 2	Interactive (logon at keyboard and screen of system)

- 3	Network (i.e. connection to shared folder on this computer from elsewhere on network)

- 4	Batch (i.e. scheduled task)

- 5	Service (Service startup)

- 7	Unlock (i.e. unnattended workstation with password protected screen saver)

- 8	NetworkCleartext (Logon with credentials sent in the clear text. Most often indicates a logon to IIS with "basic authentication") See this article for more information.

- 9	NewCredentials such as with RunAs or mapping a network drive with alternate credentials.  This logon type does not seem to show up in any events.  If you want to track users attempting to logon with alternate credentials see 4648.  MS says "A caller cloned its current token and specified new credentials for outbound connections. The new logon session has the same local identity, but uses different credentials for other network connections."

- 10 RemoteInteractive (Terminal Services, Remote Desktop or Remote Assistance)

- 11 CachedInteractive (logon with cached domain credentials such as when logging on to a laptop when away from the network)

And also the protocol used to login :
- Kerberos

- NTLM V1 or V2

- Negotiate (by default, it's Kerberos)

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
