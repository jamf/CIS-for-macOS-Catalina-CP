# CIS for macOS Big Sur - Script and Configuration Profile Remediation
## INFO:

Refers to document CIS_Apple_macOS_11.0_Benchmark_v1.1.0.pdf, available at https://benchmarks.cisecurity.org

## USAGE:
### Manual Usage

These scripts are intended to be used by jamf. However, if you want to manually benchmark your own **Big Sur** laptop, you can do so via the following steps:

* Ensure that `/Library/Application Support/` exists. Note that sudo is required for its creation
* Update `CIS Scripts/1_Set_Organization_Priorities.sh` if necessary. Checks can be enabled and disabled by changing their corresponding boolean values
* Run `CIS Scripts/2_Security_Audit_Compliance.sh` with sudo to run the benchmark
* You can now get a list of all fails by using `Extension Attributes/2.5_Audit_List.sh` or remediate the fails using `CIS Scripts/3_Security_Remediation.sh` (sudo required as some checks cannot be run by standard users)

* Create Extension Attributes using the following scripts:
### 2.5_Audit_List Extension Attribute

Set as Data Type "String."
Reads contents of /Library/Application Support/SecurityScoring/org_audit file and records to Jamf Pro inventory record.

### 2.6_Audit_Count Extension Attribute

Set as Data Type "Integer." 
Reads contents of /Library/Application Support/SecurityScoring/org_audit file and records count of items to Jamf Pro inventory record. Usable with smart group logic (2.6_Audit_Count greater than 0) to immediately determine computers not in compliance.

Add the following scripts to your Jamf Pro  
* 1_Set_Organization_Priorities  
* 2_Security_Audit_Compliance
* 3_Security_Remediation

Script __1_Set_Organization_Priorities__ will need additional configuration prior to deployment.

### 1_Set_Organization_Priorities

Admins set organizational compliance for each listed item, which gets written to plist. The values default to "true," meaning if an organization wishes to disregard a given item they must set the value to false by changing the associated comment:

OrgScore1_1="true" or OrgScore1_1="false"

### 2_Security_Audit_Complaince

Configure the following variables in the script:

The script writes to /Library/Application Support/SecurityScoring/org_security_score.plist by default.

* Create a single Jamf Policy using all three scripts.  
1_Set_Organization_Priorities - Script Priority: Before  
2_Security_Audit_Compliance Script Priority: Before  
3_Security_Remediation - Script Priority: Before  
2_Security_Audit_Compliance - Script Priority: After  
Maintenance Payload - Update Inventory

* Policy: Some recurring trigger to track compliance over time. 


NOTES: 

* Item "1.1 Verify all Apple provided software is current" is disabled by default.
* Item "2.1.2 Turn off Bluetooth "Discoverable" mode when not pairing devices - not applicable to 10.9 and higher."
	Starting with OS X (10.9) Bluetooth is only set to Discoverable when the Bluetooth System Preference is selected. 
	To ensure that the computer is not Discoverable do not leave that preference open.
* Item "2.6.6 Enable Location Services (Not Scored)" is disabled by default.
	As of macOS 10.12.2, Location Services cannot be enabled/monitored programmatically.
	It is considered user opt in.
* Item "2.6.7 Monitor Location Services Access (Not Scored)" is disabled by default.
	As of macOS 10.12.2, Location Services cannot be enabled/monitored programmatically.
	It is considered user opt in.
* Item "2.7.1 Time Machine Auto-Backup " is disabled by default.
	Time Machine is typically not used as an Enterprise backup solution
* Item "2.7.2 Time Machine Volumes Are Encrypted (Not Scored)" is disabled by default.
	Time Machine is typically not used as an Enterprise backup solution
* Item "2.10 Securely delete files as needed (Not Scored)" is disabled by default.
	With the wider use of FileVault and other encryption methods and the growing use of Solid State Drives
	the requirements have changed and the "Secure Empty Trash" capability has been removed from the GUI.
* Item "4.3 Create network specific locations (Not Scored)" is disabled by default.
* Item "5.5 Automatically lock the login keychain for inactivity" is disabled by default.
* Item "5.6 Ensure login keychain is locked when the computer sleeps" is disabled by default.
* Item "5.15 Do not enter a password-related hint (Not Scored)" is disabled by default.
	Not needed if 6.1.2 Disable "Show password hints" is enforced.
* Item "5.17 Secure individual keychains and items (Not Scored)" is disabled by default.
* Item "5.8 Create specialized keychains for different purposes (Not Scored)" is disabled by default.
* Item "6.3 Safari disable Internet Plugins for global use (Not Scored)" is disabled by default.


### 2_Security_Audit_Compliance

Run this before and after 3_Security_Remediation to audit the Remediation
Reads the plist at /Library/Application Support/SecurityScoring/org_security_score.plist. For items prioritized (listed as "true,") the script queries against the current computer/user environment to determine compliance against each item.

Non-compliant items are recorded at /Library/Application Support/SecurityScoring/org_audit


### 3_Security_Remediation

Run 2_Security_Audit_Compliance after to audit the Remediation
Reads the plist at /Library/Application Support/SecurityScoring/org_security_score.plist. For items prioritized (listed as "true,") the script applies recommended remediation actions for the client/user.

