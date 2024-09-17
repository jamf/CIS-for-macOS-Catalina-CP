# Content here is depreciated. Please go to https://github.com/usnistgov/macos_security for current security benchmarks and workflows


## CIS for macOS Catalina - Script and Configuration Profile Remediation
## INFO:

Refers to document CIS_Apple_OSX_10.15_Benchmark_v1.0.0.pdf, available at https://benchmarks.cisecurity.org

## USAGE:
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

SCORED CIS EXCEPTIONS:

- Does not implement `pwpolicy` commands (5.2.1 - 5.2.8)

- Audits but does not actively remediate (due to alternate profile/policy functionality within Jamf Pro):
* 2.4.4 Disable Printer Sharing
* 2.5.1.1 Enable FileVault
* 5.19 System Integrity Protection status

- Audits but does not remediate (due to requirement to review the device)
* 3.4 Control access to audit records

## REMEDIATED USING CONFIGURATION PROFILES:
The following Configuration profiles are available in mobileconfig and plist form.  If you wish to change a particular setting, edit the plist in question.  Mobileconfigs can be uploaded to Jamf Pro Configuration Profiles as is and plists can be added to a new Configuration Profile as Custom Payloads.

### CIS 10.15 Custom Settings mobileconfig
* 1.2 Enable Auto Update
* 1.5 Enable system data files and security update installed
* 2.9 Enable Secure Keyboard Entry in terminal.app 
* 4.1 Disable Bonjour advertising service 
* 6.1.4 Disable "Allow guests to connect to shared folders" 
* 6.3 Disable the automatic run of safe files in Safari

### CIS 10.15 LoginWindow Security_and_Privacy ScreenSaver mobileconfig
* 2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver 
* 2.3.2 Secure screen saver corners 
* 2.3.3 Set a screen corner to Start Screen Saver 
* 2.5.2 Enable Gatekeeper
* 2.5.3 Enable Firewall 
* 2.5.4 Enable Firewall Stealth Mode 
* 2.5.5 Review Application Firewall Rules 
* 5.8 Disable automatic login 
* 5.9 Require a password to wake the computer from sleep or screen saver
* 5.13 Create a custom message for the Login Screen
* 5.16 Disable Fast User Switching (Not Scored)
* 6.1.1 Display login window as name and password 
* 6.1.2 Disable "Show password hints" 
* 6.1.3 Disable guest account 

### CIS 10.15 Restrictions mobileconfig
* 2.4.10  Disable Content Caching (Not Scored) - Restrictions payload > Functionality > Allow Content Caching (unchecked)
* 2.5.8 Disable sending diagnostic and usage data to Apple - Restrictions payload > Allow Diagnostic Submission (unchecked)
* 2.6.1 iCloud system configuration
* Includes:
* Disable preference pane (Not Scored) - Restrictions payload > Preferences > disable selected items > iCloud
* Disable the use of iCloud password for local accounts (Not Scored)  - Restrictions payload > Functionality > Allow use of iCloud password for local accounts (unchecked)
* Disable iCloud Back to My Mac (Not Scored) - Restrictions payload > Functionality > Allow iCloud Back to My Mac (unchecked)
* Disable iCloud Find My Mac (Not Scored) - Restrictions payload > Functionality > Allow iCloud Find My Mac (unchecked)
* Disable iCloud Bookmarks (Not Scored) - Restrictions payload > Functionality > Allow iCloud Bookmarks (unchecked)
* Disable iCloud Mail (Not Scored)  - Restrictions payload > Functionality > Allow iCloud Mail (unchecked)
* Disable iCloud Calendar (Not Scored) - Restrictions payload > Functionality > Allow iCloud Calendar (unchecked)
* Disable iCloud Reminders (Not Scored) - Restrictions payload > Functionality > Allow iCloud Reminders (unchecked)
* Disable iCloud Contacts (Not Scored) - Restrictions payload > Functionality > Allow iCloud Contacts (unchecked)
* Disable iCloud Notes (Not Scored) - Restrictions payload > Functionality > Allow iCloud Notes (unchecked)
* 2.6.2 Disable iCloud keychain (Not Scored) - Restrictions payload > Functionality > Allow iCloud Keychain (unchecked)
* 2.6.3 Disable iCloud Drive (Not Scored) - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
* 2.6.4 Disable iCloud Drive Document sync - Restrictions payload > Functionality > Allow iCloud Desktop & Documents (unchecked)
* 2.6.5 Disable iCloud Drive Desktop sync - Restrictions payload > Functionality > Allow iCloud Desktop & Documents (unchecked)2.6.8 Disable sending diagnostic and usage data to Apple
