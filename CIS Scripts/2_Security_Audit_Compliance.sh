#!/bin/bash

####################################################################################################
#
# Copyright (c) 2017, Jamf, LLC.  All rights reserved.
#
#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are met:
#               * Redistributions of source code must retain the above copyright
#                 notice, this list of conditions and the following disclaimer.
#               * Redistributions in binary form must reproduce the above copyright
#                 notice, this list of conditions and the following disclaimer in the
#                 documentation and/or other materials provided with the distribution.
#               * Neither the name of the JAMF Software, LLC nor the
#                 names of its contributors may be used to endorse or promote products
#                 derived from this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY JAMF SOFTWARE, LLC "AS IS" AND ANY
#       EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#       WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#       DISCLAIMED. IN NO EVENT SHALL JAMF SOFTWARE, LLC BE LIABLE FOR ANY
#       DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#       (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#       LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#       ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#       SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
####################################################################################################
# written by Katie English, Jamf October 2016
# updated for 10.12 CIS benchmarks by Katie English, Jamf February 2017
# updated to use configuration profiles by Apple Professional Services, January 2018
# updated to use REST API to update EAs instead of recon
# github.com/jamfprofessionalservices
# updated for 10.13 CIS benchmarks by Erin McDonald, Jamf Jan 2019
# updated for 10.15 CIS benchmarks by Erin McDonald, Jamf 2020

# USAGE
# Reads from plist at /Library/Application Support/SecurityScoring/org_security_score.plist by default.
# For "true" items, runs query for current computer/user compliance.
# Non-compliant items are logged to /Library/Application Support/SecurityScoring/org_audit
# Variables

Defaults="/usr/bin/defaults"


# DO NOT EDIT BELOW THIS LINE
####################################################################################################

plistlocation="/Library/Application Support/SecurityScoring/org_security_score.plist"
auditfilelocation="/Library/Application Support/SecurityScoring/org_audit"
currentUser="$(python -c 'from SystemConfiguration import SCDynamicStoreCopyConsoleUser; import sys; username = (SCDynamicStoreCopyConsoleUser(None, None, None) or [None])[0]; username = [username,""][username in [u"loginwindow", None, u""]]; sys.stdout.write(username + "\n");')"
hardwareUUID="$(/usr/sbin/system_profiler SPHardwareDataType | grep "Hardware UUID" | awk -F ": " '{print $2}' | xargs)"

logFile="/Library/Application Support/SecurityScoring/remediation.log"

osVersion="$(sw_vers -productversion)"
if [ "$osVersion" < 11 ]; then
	echo "This script does not support Catalina. Please use https://github.com/jamf/CIS-for-macOS-Catalina-CP instead"
	exit 0
fi


if [[ $(tail -n 1 "$logFile") = *"Remediation complete" ]]; then
	echo "Append to existing logFile"
 	echo "$(date -u)" "Beginning Audit" >> "$logFile"
else
 	echo "Create new logFile"
 	echo "$(date -u)" "Beginning Audit" > "$logFile"	
fi

if [[ ! -e $plistlocation ]]; then
	echo "No scoring file present"
	exit 0
fi

# Cleanup audit file to start fresh
[ -f "$auditfilelocation" ] && rm "$auditfilelocation"
touch "$auditfilelocation"


# 1.1 Verify all Apple provided software is current
# Verify organizational score
Audit1_1="$($Defaults read "$plistlocation" OrgScore1_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit1_1" = "1" ]; then
	countAvailableSUS="$(softwareupdate -l | grep "*" | wc -l | tr -d ' ')"
	# If client fails, then note category in audit file
	if [ "$countAvailableSUS" = "0" ]; then
		echo "$(date -u)" "1.1 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore1_1 -bool false; else
		echo "* 1.1 Verify all Apple provided software is current" >> "$auditfilelocation"
		echo "$(date -u)" "1.1 fix" | tee -a "$logFile"
	fi
fi

# 1.2 Enable Auto Update
# Configuration Profile - Custom payload > com.apple.SoftwareUpdate.plist > AutomaticCheckEnabled=true, AutomaticDownload=true
# Verify organizational score
Audit1_2="$($Defaults read "$plistlocation" OrgScore1_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit1_2" = "1" ]; then
	# Check to see if the preference and key exist. If not, write to audit log. Presuming: Unset = not secure state.
	CP_automaticUpdates="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'AutomaticCheckEnabled = 1')"
	if [[ "$CP_automaticUpdates" -gt "0" ]]; then
		echo "$(date -u)" "1.2 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore1_2 -bool false; else
		automaticUpdates="$($Defaults read /Library/Preferences/com.apple.SoftwareUpdate | /usr/bin/grep -c 'AutomaticCheckEnabled = 1')"
		if [[ "$automaticUpdates" -gt "0" ]]; then
			echo "$(date -u)" "1.2 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore1_2 -bool false; else
			echo "* 1.2 Enable Auto Update" >> "$auditfilelocation"
			echo "$(date -u)" "1.2 fix" | tee -a "$logFile"
		fi
	fi
fi

# 1.3 Enable Download new updates when available
# Verify organizational score
Audit1_3="$($Defaults read "$plistlocation" OrgScore1_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit1_3" = "1" ]; then
	# Check to see if the preference and key exist. If not, write to audit log. Presuming: Unset = not secure state.
		CP_automaticAppUpdates="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'AutomaticDownload = 1')"
		if [[ "$CP_automaticAppUpdates" -gt "0" ]]; then
			echo "$(date -u)" "1.3 passed cp" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore1_3 -bool false; else
	automaticAppUpdates="$($Defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload)"
	# If client fails, then note category in audit file
	if [ "$automaticAppUpdates" = "1" ]; then
		echo "$(date -u)" "1.3 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore1_3 -bool false; else
		echo "* 1.3 Enable app update installs" >> "$auditfilelocation"
		echo "$(date -u)" "1.3 fix" | tee -a "$logFile"
	fi
	fi
fi

# 1.4 Enable app updates 
# Configuration Profile - Software Update - Automatically install App Store app updates
# Verify organizational score
Audit1_4="$($Defaults read "$plistlocation" OrgScore1_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit1_4" = "1" ]; then
	# Check to see if the preference and key exist. If not, write to audit log. Presuming: Unset = not secure state.
		CP_automaticAppUpdates="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'AutomaticInstallAppUpdates = 1')"
		if [[ "$CP_automaticAppUpdates" -gt "0" ]]; then
			echo "$(date -u)" "1.4 passed cp" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore1_4 -bool false; else
		automaticAppUpdates="$($Defaults read /Library/Preferences/com.apple.commerce AutoUpdate)"
	# If client fails, then note category in audit file
	if [ "$automaticAppUpdates" = "1" ]; then
		echo "$(date -u)" "1.4 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore1_4 -bool false; else
		echo "* 1.4 Enable app update installs" >> "$auditfilelocation"
		echo "$(date -u)" "1.4 fix" | tee -a "$logFile"
	fi
	fi
fi


# 1.5 Enable system data files and security update installs 
# Configuration Profile - Software Updates - Install security updates automatically and Install xProtect, MRT & Gatekeeper updates automatically (Jamf Pro - Automatically install configuration data and Automatcially install system data files and security updates)
# Verify organizational score
Audit1_5="$($Defaults read "$plistlocation" OrgScore1_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit1_5" = "1" ]; then
	# Check to see if the preference and key exist. If not, write to audit log. Presuming: Unset = not secure state.
	CP_criticalUpdates="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'ConfigDataInstall = 1')"
	if [[ "$CP_criticalUpdates" -gt "0" ]]; then
		echo "$(date -u)" "1.5 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore1_5 -bool false; else
		criticalUpdates="$($Defaults read /Library/Preferences/com.apple.SoftwareUpdate | /usr/bin/grep -c 'ConfigDataInstall = 1')"
		if [[ "$criticalUpdates" -gt "0" ]]; then
			echo "$(date -u)" "1.5 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore1_5 -bool false; else
			echo "* 1.5 Enable system data files and security update installs" >> "$auditfilelocation"
			echo "$(date -u)" "1.5 fix" | tee -a "$logFile"
		fi
	fi
fi

# 1.6 Enable OS X update installs 
# Configuration Profile - Software Updates - Automatically install macOS updates
# Verify organizational score
Audit1_6="$($Defaults read "$plistlocation" OrgScore1_6)"
# If organizational score is 1 or true, check status of client
if [ "$Audit1_6" = "1" ]; then
	updateRestart="$($Defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates)"
	# If client fails, then note category in audit file
	if [ "$updateRestart" = "1" ]; then
		echo "$(date -u)" "1.6 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore1_6 -bool false; else
		echo "* 1.6 Enable OS X update installs" >> "$auditfilelocation"
		echo "$(date -u)" "1.6 fix" | tee -a "$logFile"
	fi
fi

# 2.1.1 Turn off Bluetooth, if no paired devices exist
# Verify organizational score
Audit2_1_1="$($Defaults read "$plistlocation" OrgScore2_1_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_1_1" = "1" ]; then
	btPowerState="$($Defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState)"
	# If client fails, then note category in audit file
	if [ "$btPowerState" = "0" ]; then
		echo "$(date -u)" "2.1.1 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_1_1 -bool false; else
		connectable="$(system_profiler SPBluetoothDataType 2>&1| grep Connectable | awk '{print $2}' | head -1)"
		if [[ "$connectable" != "Yes" ]]; then
			echo "$(date -u)" "2.1.1 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_1_1 -bool false; else
			echo "* 2.1.1 Turn off Bluetooth, if no paired devices exist" >> "$auditfilelocation"
			echo "$(date -u)" "2.1.1 fix" | tee -a "$logFile"
		fi
	fi
fi

# 2.1.2 Show Bluetooth status in menu bar
# Verify organizational score
Audit2_1_2="$($Defaults read "$plistlocation" OrgScore2_1_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_1_2" = "1" ]; then
	btMenuBar="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.systemuiserver menuExtras | grep -c Bluetooth.menu)"
	# If client fails, then note category in audit file
	if [ "$btMenuBar" = "0" ]; then
		echo "* 2.1.2 Show Bluetooth status in menu bar" >> "$auditfilelocation"
		echo "$(date -u)" "2.1.2 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "2.1.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_1_2 -bool false
	fi
fi

### 2.2.1 Enable "Set time and date automatically" (Not Scored)
# Verify organizational score
Audit2_2_1="$($Defaults read "$plistlocation" OrgScore2_2_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_2_1" = "1" ]; then
	SetTimeAndDateAutomatically="$(systemsetup -getusingnetworktime | awk '{print $3}')"
	# If client fails, then note category in audit file
	if [ "$SetTimeAndDateAutomatically" = "On" ]; then
	 	echo "$(date -u)" "2.2.1 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_2_1 -bool false; else
		echo "* 2.2.1 Enable Set time and date automatically" >> "$auditfilelocation"
		echo "$(date -u)" "2.2.1 fix" | tee -a "$logFile"
	fi
fi

# 2.2.2 Ensure time set is within appropriate limits
# Not audited - only enforced if identified as priority
# Verify organizational score
Audit2_2_2="$($Defaults read "$plistlocation" OrgScore2_2_2)"
# If organizational score is 1 or true, check status of client
# if [ "$Audit2_2_2" = "1" ]; then
# sync time 
# fi

# 2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver 
# Configuration Profile - LoginWindow payload > Options > Start screen saver after: 20 Minutes of Inactivity
# Verify organizational score
Audit2_3_1="$($Defaults read "$plistlocation" OrgScore2_3_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_3_1" = "1" ]; then
	CP_screenSaverTime="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep idleTime | awk '{print $3-0}')"
	# If client fails, then note category in audit file
	if [[ "$CP_screenSaverTime" -le "1200" ]] && [[ "$CP_screenSaverTime" != "" ]]; then
		echo "$(date -u)" "2.3.1 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_3_1 -bool false; else
		screenSaverTime="$($Defaults read /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.screensaver."$hardwareUUID".plist idleTime)"
		if [[ "$screenSaverTime" -le "1200" ]] && [[ "$screenSaverTime" != "" ]]; then
			echo "$(date -u)" "2.3.1 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_3_1 -bool false; else
			echo "* 2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver" >> "$auditfilelocation"
			echo "$(date -u)" "2.3.1 fix" | tee -a "$logFile"
		fi
	fi
fi

# 2.3.2 Secure screen saver corners 
# Configuration Profile - Custom payload > com.apple.dock > wvous-tl-corner=0, wvous-br-corner=5, wvous-bl-corner=0, wvous-tr-corner=0
# Verify organizational score
Audit2_3_2="$($Defaults read "$plistlocation" OrgScore2_3_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_3_2" = "1" ]; then
	CP_corner="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(\"wvous-bl-corner\" =|\"wvous-tl-corner\" =|\"wvous-tr-corner\" =|\"wvous-br-corner\" =)')"
	# If client fails, then note category in audit file
	if [[ "$CP_corner" != *"6"* ]] && [[ "$CP_corner" != "" ]]; then
		echo "$(date -u)" "2.3.2 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_3_2 -bool false; else
		bl_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner)"
		tl_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner)"
		tr_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner)"
		br_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner)"
		if [[ "$bl_corner" != "6" ]] && [[ "$tl_corner" != "6" ]] && [[ "$tr_corner" != "6" ]] && [[ "$br_corner" != "6" ]]; then
			echo "$(date -u)" "2.3.2 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_3_2 -bool false; else
			echo "* 2.3.2 Secure screen saver corners" >> "$auditfilelocation"
			echo "$(date -u)" "2.3.2 fix" | tee -a "$logFile"
		fi
	fi
fi

# 2.3.3 Familiarize users with screen lock tools or corner to Start Screen Saver 
# Configuration Profile - Custom payload > com.apple.dock > wvous-tl-corner=0, wvous-br-corner=5, wvous-bl-corner=0, wvous-tr-corner=0
# Verify organizational score
Audit2_3_3="$($Defaults read "$plistlocation" OrgScore2_3_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_3_3" = "1" ]; then
	# If client fails, then note category in audit file
	CP_corner="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(\"wvous-bl-corner\" =|\"wvous-tl-corner\" =|\"wvous-tr-corner\" =|\"wvous-br-corner\" =)')"
	if [[ "$CP_corner" = *"5"* ]] ; then
		echo "$(date -u)" "2.3.4 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_3_3 -bool false; else
		bl_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-bl-corner)"
		tl_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tl-corner)"
		tr_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-tr-corner)"
		br_corner="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.dock wvous-br-corner)"
		if [ "$bl_corner" = "5" ] || [ "$tl_corner" = "5" ] || [ "$tr_corner" = "5" ] || [ "$br_corner" = "5" ]; then
			echo "$(date -u)" "2.3.3 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_3_3 -bool false; else
			echo "* 2.3.3 Familiarize users with screen lock tools or corner to Start Screen Saver" >> "$auditfilelocation"
			echo "$(date -u)" "2.3.3 fix" | tee -a "$logFile"
		fi
	fi
fi


# 2.4.1 Disable Remote Apple Events 
# Verify organizational score
Audit2_4_1="$($Defaults read "$plistlocation" OrgScore2_4_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_1" = "1" ]; then
	remoteAppleEvents="$(systemsetup -getremoteappleevents | awk '{print $4}')"
	# If client fails, then note category in audit file
	if [ "$remoteAppleEvents" = "Off" ]; then
	 	echo "$(date -u)" "2.4.1 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_4_1 -bool false; else
		echo "* 2.4.1 Disable Remote Apple Events" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.1 fix" | tee -a "$logFile"
	fi
fi

# 2.4.2 Disable Internet Sharing 
# Verify organizational score
Audit2_4_2="$($Defaults read "$plistlocation" OrgScore2_4_2)"
# If organizational score is 1 or true, check status of client
# If client fails, then note category in audit file
if [ "$Audit2_4_2" = "1" ]; then
	if [ -e /Library/Preferences/SystemConfiguration/com.apple.nat.plist ]; then
		natAirport="$(/usr/libexec/PlistBuddy -c "print :NAT:AirPort:Enabled" /Library/Preferences/SystemConfiguration/com.apple.nat.plist)"
		natEnabled="$(/usr/libexec/PlistBuddy -c "print :NAT:Enabled" /Library/Preferences/SystemConfiguration/com.apple.nat.plist)"
		natPrimary="$(/usr/libexec/PlistBuddy -c "print :NAT:PrimaryInterface:Enabled" /Library/Preferences/SystemConfiguration/com.apple.nat.plist)"
        forwarding="$(sysctl net.inet.ip.forwarding | awk '{ print $NF }')"
		if [ "$natAirport" = "true" ] || [ "$natEnabled" = "true" ] || [ "$natPrimary" = "true" ] || [ "$forwarding" = "1" ]; then
			echo "* 2.4.2 Disable Internet Sharing"  >> "$auditfilelocation"
			echo "$(date -u)" "2.4.2 fix" | tee -a "$logFile"
        else
			echo "$(date -u)" "2.4.2 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_4_2 -bool false
		fi
    else
		echo "$(date -u)" "2.4.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_4_2 -bool false
	fi
fi

# 2.4.3 Disable Screen Sharing 
# Verify organizational score
Audit2_4_3="$($Defaults read "$plistlocation" OrgScore2_4_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_3" = "1" ]; then
	# If client fails, then note category in audit file
	screenSharing="$(launchctl list | egrep -c screensharing)"
	if [ "$screenSharing" -gt 0 ]; then
		echo "* 2.4.3 Disable Screen Sharing" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.3 fix" | tee -a "$logFile"; else
	 	echo "$(date -u)" "2.4.3 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_4_3 -bool false
	fi
fi

# 2.4.4 Disable Printer Sharing 
# Verify organizational score
Audit2_4_4="$($Defaults read "$plistlocation" OrgScore2_4_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_4" = "1" ]; then
	# If client fails, then note category in audit file
	printerSharing="$(/usr/sbin/cupsctl | grep -c "share_printers=0")"
	if [ "$printerSharing" != "0" ]; then
	 	echo "$(date -u)" "2.4.4 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_4_4 -bool false; else
		echo "* 2.4.4 Disable Printer Sharing" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.4 fix" | tee -a "$logFile"
	fi
fi

# 2.4.5 Disable Remote Login 
# Verify organizational score
Audit2_4_5="$($Defaults read "$plistlocation" OrgScore2_4_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_5" = "1" ]; then
	remoteLogin="$(/usr/sbin/systemsetup -getremotelogin | awk '{print $3}')"
	# If client fails, then note category in audit file
	if [ "$remoteLogin" = "Off" ]; then
	 	echo "$(date -u)" "2.4.5 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_4_5 -bool false; else
		echo "* 2.4.5 Disable Remote Login" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.5 fix" | tee -a "$logFile"
	fi
fi

# 2.4.6 Disable DVD or CD Sharing 
# Verify organizational score
Audit2_4_6="$($Defaults read "$plistlocation" OrgScore2_4_6)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_6" = "1" ]; then
	discSharing="$(launchctl list | egrep ODSAgent)"
	# If client fails, then note category in audit file
	if [ "$discSharing" = "" ]; then
	 	echo "$(date -u)" "2.4.6 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_4_6 -bool false; else
		echo "* 2.4.6 Disable DVD or CD Sharing" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.6 fix" | tee -a "$logFile"
	fi
fi

# 2.4.7 Disable Bluetooth Sharing
# Verify organizational score
Audit2_4_7="$($Defaults read "$plistlocation" OrgScore2_4_7)"
# If organizational score is 1 or true, check status of client and user
if [ "$Audit2_4_7" = "1" ]; then
	btSharing="$(/usr/libexec/PlistBuddy -c "print :PrefKeyServicesEnabled"  /Users/"$currentUser"/Library/Preferences/ByHost/com.apple.Bluetooth."$hardwareUUID".plist)"
	# If client fails, then note category in audit file
	if [ "$btSharing" = "true" ]; then
		echo "* 2.4.7 Disable Bluetooth Sharing" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.7 fix" | tee -a "$logFile"; else
	 	echo "$(date -u)" "2.4.7 passed" | tee -a "$logFile"
	 	$Defaults write "$plistlocation" OrgScore2_4_7 -bool false
	fi
fi

# 2.4.8 Disable File Sharing
# Verify organizational score
Audit2_4_8="$($Defaults read "$plistlocation" OrgScore2_4_8)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_8" = "1" ]; then
	afpEnabled="$(launchctl list | egrep AppleFileServer)"
	smbEnabled="$(launchctl list | egrep smbd)"
	# If client fails, then note category in audit file
	if [ "$afpEnabled" = "" ] && [ "$smbEnabled" = "" ]; then
 		echo "$(date -u)" "2.4.8 passed" | tee -a "$logFile"
 		$Defaults write "$plistlocation" OrgScore2_4_8 -bool false; else
		echo "* 2.4.8 Disable File Sharing" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.8 fix" | tee -a "$logFile"
	fi
fi

# 2.4.9 Disable Remote Management
# Verify organizational score
Audit2_4_9="$($Defaults read "$plistlocation" OrgScore2_4_9)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_9" = "1" ]; then
	remoteManagement="$(ps -ef | egrep ARDAgent | grep -c "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent")"
	# If client fails, then note category in audit file
	if [ "$remoteManagement" = "1" ]; then
 		echo "$(date -u)" "2.4.9 passed" | tee -a "$logFile"
 		$Defaults write "$plistlocation" OrgScore2_4_9 -bool false; else
		echo "* 2.4.9 Disable Remote Management" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.9 fix" | tee -a "$logFile"
	fi
fi

# 2.4.10 Disable Content Caching
# Verify organizational score
Audit2_4_10="$($Defaults read "$plistlocation" OrgScore2_4_10)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_10" = "1" ]; then
	contentCacheStatus="$(/usr/bin/AssetCacheManagerUtil status 2>&1 | grep -c "Activated: false")"
	# If client fails, then note category in audit file
	if [ "$contentCacheStatus" == 1 ]; then
 		echo "$(date -u)" "2.4.10 passed" | tee -a "$logFile"
 		$Defaults write "$plistlocation" OrgScore2_4_10 -bool false; else
		echo "* 2.4.10 Disable Disable Content Caching" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.10 fix" | tee -a "$logFile"
	fi
fi

# 2.4.11 Disable Media Sharing
# Verify organizational score
Audit2_4_11="$($Defaults read "$plistlocation" OrgScore2_4_11)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_4_11" = "1" ]; then
	mediaSharingStatusHome=$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.amp.mediasharingd.plist home-sharing-enabled)
	mediaSharingStatusPublic=$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.amp.mediasharingd.plist public-sharing-enabled)
	# If client fails, then note category in audit file
	if [ "$mediaSharingStatusHome" == 0 ] && [ "$mediaSharingStatusPublic" == 0 ]; then
 		echo "$(date -u)" "2.4.11 passed" | tee -a "$logFile"
 		$Defaults write "$plistlocation" OrgScore2_4_11 -bool false
		elif [ "$mediaSharingStatusHome" = "" ] && [ "$mediaSharingStatusPublic" = "" ]; then
			echo "$(date -u)" "2.4.11 passed" | tee -a "$logFile"
			 $Defaults write "$plistlocation" OrgScore2_4_11 -bool false; else
		echo "* 2.4.11 Disable Disable Media Sharing" >> "$auditfilelocation"
		echo "$(date -u)" "2.4.11 fix" | tee -a "$logFile"
	fi
fi


# 2.5.1.1 Enable FileVault 
# Verify organizational score
# Audit only.  Does not remediate
Audit2_5_1_1="$($Defaults read "$plistlocation" OrgScore2_5_1_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_5_1_1" = "1" ]; then
	filevaultEnabled="$(fdesetup status | awk '{print $3}')"
	# If client fails, then note category in audit file
	if [ "$filevaultEnabled" = "Off." ]; then
		echo "* 2.5.1.1 Enable FileVault" >> "$auditfilelocation"
		echo "$(date -u)" "2.5.1.1 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "2.5.1.1 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_1_1 -bool false	
	fi
fi

# 2.5.1.2 Ensure all user storage APFS Volumes are encrypted
# Verify organizational score
# Audit only.  Does not remediate
Audit2_5_1_2="$($Defaults read "$plistlocation" OrgScore2_5_1_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_5_1_2" = "1" ]; then
	apfsyes="$(diskutil ap list)"
	if [ "$apfsyes" != "No APFS Containers found" ]; then
		DUINFO=$(diskutil info /)
		LV_UUID=$(echo "$DUINFO" | awk '/\/ Partition UUID/ {print $5;exit}')
					# Get the APFS Container ID for the boot drive's APFS volume.
					CONTAINER_ID=$(echo "$DUINFO" | awk '/Part of Whole/ {print $4;exit}')
					APFSINFO=$(diskutil ap list "$CONTAINER_ID")
					APVOLINFO=$(echo "$APFSINFO" | grep -A7 "$LV_UUID")
					ENCRYPTION=$(echo "$APVOLINFO" | awk '/FileVault/ {print $3;exit}')
					if [ "$ENCRYPTION" != "Yes" ]; then
						echo "* 2.5.1.2 Ensure all user storage APFS Volumes are encrypted" >> "$auditfilelocation"
						echo "$(date -u)" "2.5.1.2 fix" | tee -a "$logFile"; else 
						echo "$(date -u)" "2.5.1.2 passed" | tee -a "$logFile"
						$Defaults write "$plistlocation" OrgScore2_5_1_2 -bool false	
						fi
					else 
					echo "$(date -u)" "2.5.1.2 not applicable, CoreStorage storage enabled" | tee -a "$logFile"
					fi
				fi

	

# 2.5.1.3 Ensure all user storage CoreStorage Volumes are encrypted
# Verify organizational score
# Audit only.  Does not remediate
Audit2_5_1_3="$($Defaults read "$plistlocation" OrgScore2_5_1_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_5_1_3" = "1" ]; then
	apfsyes="$(diskutil ap list)"
	if [ "$apfsyes" == "No APFS Containers found" ]; then
		# get Logical Volume Family
		LFV="$(diskutil cs list | grep "Logical Volume Family" | awk '/Logical Volume Family/ {print $5}')"
		# Check encryption status is complete
		EncryptStatus="$( diskutil cs "$LFV" | awk '/Conversion Status/ {print $3}')"
		if [ "$EncryptStatus" != "Complete" ]; then
		echo "* 2.5.1.3 Ensure all user CoreStorage volumes encrypted" >> "$auditfilelocation"
		echo "$(date -u)" "2.5.1.3 fix" | tee -a "$logfile"; else 
		echo "$(date -u)" "2.5.1.3 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_1_3 -bool false	
		fi
	else 
	echo "$(date -u)" "2.5.1.3 not applicable, APFS storage enabled" | tee -a "$logFile"
	fi
fi
	

# 2.5.2.1 Enable Gatekeeper 
# Configuration Profile - Security and Privacy payload > General > Gatekeeper > Mac App Store and identified developers (selected)
# Verify organizational score
Audit2_5_2.1="$($Defaults read "$plistlocation" OrgScore2_5_2_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_5_2_1" = "1" ]; then
	CP_gatekeeperEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'EnableAssessment = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_gatekeeperEnabled" -gt "0" ]] ; then
		echo "$(date -u)" "2.5.2.1 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_2_1 -bool false; else
		gatekeeperEnabled="$(spctl --status | grep -c "assessments enabled")"
		if [ "$gatekeeperEnabled" = "1" ]; then
			echo "$(date -u)" "2.5.2.1 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_5_2_1 -bool false; else
			echo "* 2.5.2.1 Enable Gatekeeper" >> "$auditfilelocation"
			echo "$(date -u)" "2.5.2.1 fix" | tee -a "$logFile"
		fi
	fi
fi

# 2.5.2.2 Enable Firewall 
# Configuration Profile - Security and Privacy payload > Firewall > Enable Firewall (checked)
# Verify organizational score
Audit2_5_2_2="$($Defaults read "$plistlocation" OrgScore2_5_2_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_5_2_2" = "1" ]; then
	CP_firewallEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'EnableFirewall = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_firewallEnabled" -gt "0" ]] ; then
		echo "$(date -u)" "2.5.2.2 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_2_2 -bool false; else
		firewallEnabled="$($Defaults read /Library/Preferences/com.apple.alf globalstate)"
		if [ "$firewallEnabled" = "0" ]; then
			echo "* 2.5.2.2 Enable Firewall" >> "$auditfilelocation"
			echo "$(date -u)" "2.5.2.2 fix" | tee -a "$logFile"; else
			echo "$(date -u)" "2.5.2.2 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_5_2_2 -bool false
		fi
	fi
fi

# 2.5.2.3 Enable Firewall Stealth Mode 
# Configuration Profile - Security and Privacy payload > Firewall > Enable stealth mode (checked)
# Verify organizational score
Audit2_5_2_3="$($Defaults read "$plistlocation" OrgScore2_5_2_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_5_2_3" = "1" ]; then
	CP_stealthEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'EnableStealthMode = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_stealthEnabled" -gt "0" ]] ; then
		echo "$(date -u)" "2.5.2.3 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_2_3 -bool false; else
		stealthEnabled="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | awk '{print $3}')"
		if [ "$stealthEnabled" = "enabled" ]; then
			echo "$(date -u)" "2.5.2.3 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_5_2_3 -bool false; else
			echo "* 2.5.2.3 Enable Firewall Stealth Mode" >> "$auditfilelocation"
			echo "$(date -u)" "2.5.2.3 fix" | tee -a "$logFile"
		fi
	fi
fi

# 2.5.3 Enable Location Services
# Verify organizational score
Audit2_5_3="$($Defaults read "$plistlocation" OrgScore2_5_3)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit2_5_3" = "1" ]; then
       auditdEnabled=$(launchctl print-disabled system | grep -c '"com.apple.locationd" => true')
       if [ "$auditdEnabled" = "0" ]; then
           echo "$(date -u)" "2.5.3 passed" | tee -a "$logFile"
           $Defaults write "$plistlocation" OrgScore2_5_3 -bool false
       else
           echo "* 2.5.3 Enable Location Services" >> "$auditfilelocation"
           echo "$(date -u)" "2.5.3 fix" | tee -a "$logFile"
       fi
fi

# 2.5.5 Disable sending diagnostic and usage data to Apple
# Verify organizational score
Audit2_5_5="$($Defaults read "$plistlocation" OrgScore2_5_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_5_5" = "1" ]; then
CP_disableDiagnostic="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowDiagnosticSubmission = 0')"
	# If client fails, then note category in audit file
	if [[ "$CP_disableDiagnostic" -gt "0" ]] ; then
		echo "$(date -u)" "2.5.5 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_5 -bool false; else
	AppleDiagn=$($Defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit)
	if [ "$AppleDiagn" == 1 ]; then 
		/bin/echo "* 2.5.5 Disable sending diagnostic and usage data to Apple" >> "$auditfilelocation"
		echo "$(date -u)" "2.5.5 fix Disable sending diagnostic and usage data to Apple" | tee -a "$logFile"; else
		echo "$(date -u)" "2.5.5 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_5 -bool false
		fi
	fi
fi

# 2.5.6 Limit Ad tracking and personalized Ads
# Verify organizational score
Audit2_5_6="$($Defaults read "$plistlocation" OrgScore2_5_6)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_5_6" = "1" ]; then
	if [ "$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.AdLib.plist allowApplePersonalizedAdvertising)" = "0" ]; then
		echo "$(date -u)" "2.5.6 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_5_6 -bool false
	else
		echo "* 2.5.6 Review Limit Ad tracking and personalized Ads" >> "$auditfilelocation"
		echo "$(date -u)" "2.5.6 fix" | tee -a "$logFile"
	fi
fi

# 2.6.1 iCloud configuration (Check for iCloud accounts) (Not Scored)
# Verify organizational score
Audit2_6_1="$($Defaults read "$plistlocation" OrgScore2_6_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_6_1" = "1" ]; then
	over500=$( /usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 { print $1 }' )
	for EachUser in $over500 ;
	do
		UserHomeDirectory=$(/usr/bin/dscl . -read /Users/"$EachUser" NFSHomeDirectory | /usr/bin/awk '{print $2}')
		CheckForiCloudAccount="$($Defaults read "$UserHomeDirectory/Library/Preferences/MobileMeAccounts" Accounts | /usr/bin/grep -c 'AccountDescription = iCloud')"
		# If client fails, then note category in audit file
		if [[ "$CheckForiCloudAccount" -gt "0" ]] ; then
			/bin/echo "* 2.6.1 $EachUser has an iCloud account configured" >> "$auditfilelocation"
			echo "$(date -u)" "2.6.1 fix $EachUser iCloud account" | tee -a "$logFile"; else
			echo "$(date -u)" "2.6.1 passed $EachUser" #| tee -a "$logFile"
		fi
	done
fi

# 2.6.2 Disable iCloud keychain (Not Scored) - 
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Keychain (unchecked)
# Verify organizational score
Audit2_6_2="$($Defaults read "$plistlocation" OrgScore2_6_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_6_2" = "1" ]; then
	CP_iCloudKeychain="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudKeychainSync = 0')"
	# If client fails, then note category in audit file
	if [[ "$CP_iCloudKeychain" -gt "0" ]] ; then
		echo "$(date -u)" "2.6.2 passed CP" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_6_2 -bool false; else
		echo "* 2.6.2 Disable iCloud Keychain with configuration profile" >> "$auditfilelocation"
		echo "$(date -u)" "2.6.2 fix" | tee -a "$logFile"
	fi
fi

# 2.6.3 Disable iCloud Drive (Not Scored)
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
# Verify organizational score
Audit2_6_3="$($Defaults read "$plistlocation" OrgScore2_6_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_6_3" = "1" ]; then
	CP_iCloudDrive="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudDocumentSync = 0')"
	# If client fails, then note category in audit file
	if [[ "$CP_iCloudDrive" -gt "0" ]] ; then
		echo "$(date -u)" "2.6.3 passed CP" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_6_3 -bool false; else
		echo "* 2.6.3 Disable iCloud Drive with configuration profile" >> "$auditfilelocation"
		echo "$(date -u)" "2.6.3 fix" | tee -a "$logFile"
	fi
fi

# 2.6.4 iCloud Drive Document sync
# Configuration Profile - Restrictions payload - > Functionality > Allow iCloud Desktop & Documents (unchecked)
# Verify organizational score
Audit2_6_4="$($Defaults read "$plistlocation" OrgScore2_6_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_6_4" = "1" ]; then
	# If client fails, then note category in audit file
	CP_icloudDriveDocSync="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudDesktopAndDocuments = 0')"
	if [[ "$CP_icloudDriveDocSync" -gt "0" ]] ; then
		echo "$(date -u)" "2.6.4 passed CP" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_6_4 -bool false; else
		echo "* 2.6.4 Disable iCloud Drive Document sync with configuration profile" >> "$auditfilelocation"
		echo "$(date -u)" "2.6.4 fix" | tee -a "$logFile"
	fi
fi

# 2.6.5 iCloud Drive Desktop sync
# Configuration Profile - Restrictions payload - > Functionality > Allow iCloud Desktop & Documents (unchecked)
# Verify organizational score
Audit2_6_5="$($Defaults read "$plistlocation" OrgScore2_6_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_6_5" = "1" ]; then
	# If client fails, then note category in audit file
	CP_icloudDriveDocSync="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudDesktopAndDocuments = 0')"
	if [[ "$CP_icloudDriveDocSync" -gt "0" ]] ; then
		echo "$(date -u)" "2.6.5 passed CP" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_6_5 -bool false; else
		echo "* 2.6.5 Disable iCloud Drive Desktop sync with configuration profile" >> "$auditfilelocation"
		echo "$(date -u)" "2.6.5 fix" | tee -a "$logFile"
	fi
fi

# 2.7.1 Time Machine Auto-Backup
# Verify organizational score
Audit2_7_1="$($Defaults read "$plistlocation" OrgScore2_7_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_7_1" = "1" ]; then
	timeMachineAuto="$( $Defaults read /Library/Preferences/com.apple.TimeMachine.plist AutoBackup )"
	# If client fails, then note category in audit file
	if [ "$timeMachineAuto" != "1" ]; then
		echo "* 2.7.1 Time Machine Auto-Backup" >> "$auditfilelocation"
		echo "$(date -u)" "2.7.1 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "2.7.1 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_7_1 -bool false
	fi
fi

# 2.8 Disable "Wake for network access"
# Verify organizational score
Audit2_8="$($Defaults read "$plistlocation" OrgScore2_8)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_8" = "1" ]; then
	CP_wompEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '"Wake On LAN" = 0')"
		# If client fails, then note category in audit file
		if [[ "$CP_wompEnabled" = "3" ]] ; then
			echo "$(date -u)" "2.8 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_8 -bool false; else
			wompEnabled="$(pmset -g | grep womp | awk '{print $2}')"
			if [ "$wompEnabled" = "0" ]; then
				echo "$(date -u)" "2.8 passed" | tee -a "$logFile"
				$Defaults write "$plistlocation" OrgScore2_8 -bool false; else
				echo "* 2.8 Disable Wake for network access" >> "$auditfilelocation"
				echo "$(date -u)" "2.8 fix" | tee -a "$logFile"
			fi
		fi
fi

# 2.9 Disable Power Nap
# Verify organizational score
Audit2_9="$($Defaults read "$plistlocation" OrgScore2_9)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_9" = "1" ]; then
	napEnabled="$(pmset -g everything | grep -c 'powernap             1')"
	if [ "$napEnabled" = 0 ]; then
		echo "$(date -u)" "2.9 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_9 -bool false; else
		echo "* 2.9 Disable Power Nap" >> "$auditfilelocation"
		echo "$(date -u)" "2.9 fix" | tee -a "$logFile"
	fi
fi

# 2.10 Enable Secure Keyboard Entry in terminal.app 
# Configuration Profile - Custom payload > com.apple.Terminal > SecureKeyboardEntry=true
# Verify organizational score
Audit2_9="$($Defaults read "$plistlocation" OrgScore2_10)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_10" = "1" ]; then
	CP_secureKeyboard="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'SecureKeyboardEntry = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_secureKeyboard" -gt "0" ]] ; then
		echo "$(date -u)" "2.10 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore2_10 -bool false; else
		secureKeyboard="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.Terminal SecureKeyboardEntry)"
		iTermSecure="$($Defaults read -app iTerm 'Secure Input')"
		if [ "$secureKeyboard" = "1" ] && ["$iTermSecure" -ne "0" ]; then
			echo "$(date -u)" "2.10 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_10 -bool false; else
			echo "* 2.10 Enable Secure Keyboard Entry in terminal.app" >> "$auditfilelocation"
			echo "$(date -u)" "2.10 fix" | tee -a "$logFile"
		fi
	fi
fi

# 2.11 Ensure EFI version is valid and being regularly checked
# Audit only.  T2 chip Macs do not allow for use of eficheck
# Verify organizational score
Audit2_11="$($Defaults read "$plistlocation" OrgScore2_11)"
# If organizational score is 1 or true, check status of client
if [ "$Audit2_11" = "1" ]; then
# Check for T2 chip.  
if system_profiler SPiBridgeDataType | grep 'Model Name:' | grep -q 'T2'; then 
	echo "* 2.11 Check EFI Firmware Integrity is not supported by this Mac. T2 Chip found." >> "$auditfilelocation"
	$Defaults write "$plistlocation" OrgScore2_11 -bool false
	echo "$(date -u)" "2.11 passed" | tee -a "$logFile"
	else
		efiStatus="$(/usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check | grep -c "No changes detected")"
		if [ "$efiStatus" -gt 0 ]; then
			echo "$(date -u)" "2.11 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore2_11 -bool false
			else
				echo "* 2.11 Ensure EFI version is valid and being regularly checked" >> "$auditfilelocation"
				echo "$(date -u)" "2.11 fix" | tee -a "$logFile"
				fi
fi
fi



# 3.1 Enable security auditing
# Verify organizational score
Audit3_1="$($Defaults read "$plistlocation" OrgScore3_1)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$Audit3_1" = "1" ]; then
       auditdEnabled=$(launchctl list | grep -c auditd)
       if [ "$auditdEnabled" -gt "0" ]; then
           echo "$(date -u)" "3.1 passed" | tee -a "$logFile"
           $Defaults write "$plistlocation" OrgScore3_1 -bool false
       else
           echo "* 3.1 Enable security auditing" >> "$auditfilelocation"
           echo "$(date -u)" "3.1 fix" | tee -a "$logFile"
       fi
fi

# 3.2 Configure Security Auditing Flags
# Verify organizational score
Audit3_2="$($Defaults read "$plistlocation" OrgScore3_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit3_2" = "1" ]; then
	auditFlags="$(egrep "^flags:" /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ ${auditFlags} != *"ad"* ]];then
		echo "* 3.2 Configure Security Auditing Flags" >> "$auditfilelocation"
		echo "$(date -u)" "3.2 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "3.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore3_2 -bool false
	fi
fi

# 3.3 Retain install.log for 365 or more days 
# Verify organizational score
Audit3_3="$($Defaults read "$plistlocation" OrgScore3_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit3_3" = "1" ]; then
	installRetention="$(grep -i ttl /etc/asl/com.apple.install | awk -F'ttl=' '{print $2}')"
	# If client fails, then note category in audit file
	if [[ "$installRetention" = "" ]] || [[ "$installRetention" -lt "365" ]]; then
		echo "* 3.3 Retain install.log for 365 or more days" >> "$auditfilelocation"
		echo "$(date -u)" "3.3 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "3.3 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore3_3 -bool false
	fi
fi

# 3.4 Ensure security auditing retention
# Verify organizational score
Audit3_4="$($Defaults read "$plistlocation" OrgScore3_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit3_4" = "1" ]; then
	auditRetention="$(cat /etc/security/audit_control | egrep expire-after)"
	if [ "$auditRetention" = "expire-after:60d OR 1G" ]; then
		echo "$(date -u)" "3.4 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore3_4 -bool false; else
		echo "* 3.4 Ensure security auditing retention" >> "$auditfilelocation"
		echo "$(date -u)" "3.4 fix" | tee -a "$logFile"
		fi
	fi
		

# 3.5 Control access to audit records
# Audit only.  Remediation requires system inspection.
# Verify organizational score
Audit3_5="$($Defaults read "$plistlocation" OrgScore3_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit3_5" = "1" ]; then
	etccheck=$(ls -le /etc/security/audit_control | grep -v '\-r--------  1 root  wheel')
	varcheck=$(ls -le /var/audit | grep -v '\-r--r-----  1 root  wheel\|current\|total')
	if [[ "$etccheck" = "" ]] && [[ "$varcheck" = "" ]]; then
		echo "$(date -u)" "3.5 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore3_5 -bool false
	else
		echo "* 3.5 Control access to audit records" >> "$auditfilelocation"
		echo "$(date -u)" "3.5 fix" | tee -a "$logFile"
	fi
fi
	

# 3.6 Ensure Firewall is configured to log
# Verify organizational score
Audit3_6="$($Defaults read "$plistlocation" OrgScore3_6)"
# If organizational score is 1 or true, check status of client
if [ "$Audit3_6" = "1" ]; then
	FWlog=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode | sed -e 's/[[:space:]]*$//')
	if [ "$FWlog" = "Log mode is on" ]; then
		echo "$(date -u)" "3.6 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore3_6 -bool false; else
		echo "* 3.6 Ensure Firewall is configured to log" >> "$auditfilelocation"
		echo "$(date -u)" "3.6 fix" | tee -a "$logFile"
	fi
fi

# 4.1 Disable Bonjour advertising service 
# Configuration Profile - Custom payload > com.apple.mDNSResponder > NoMulticastAdvertisements=true
# Verify organizational score
Audit4_1="$($Defaults read "$plistlocation" OrgScore4_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit4_1" = "1" ]; then
	CP_bonjourAdvertise="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'NoMulticastAdvertisements = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_bonjourAdvertise" -gt "0" ]];then
		echo "$(date -u)" "4.1 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore4_1 -bool false
	else
		bonjourAdvertise="$( $Defaults read /Library/Preferences/com.apple.mDNSResponder | /usr/bin/grep NoMulticastAdvertisements )"
		if [ "$bonjourAdvertise" != "1" ] || [ "$boujourAdvertise" = "" ]; then
			echo "* 4.1 Disable Bonjour advertising service" >> "$auditfilelocation"
			echo "$(date -u)" "4.1 fix" | tee -a "$logFile"
		else
			echo "$(date -u)" "4.1 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore4_1 -bool false
		fi
	fi
fi

# 4.2 Enable "Show Wi-Fi status in menu bar" 
# Verify organizational score
Audit4_2="$($Defaults read "$plistlocation" OrgScore4_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit4_2" = "1" ]; then
	wifiMenuBar="$($Defaults -currentHost read com.apple.controlcenter.plist WiFi)"
	# If client fails, then note category in audit file
	if [ "$wifiMenuBar" -ne 18 ]; then
		echo "* 4.2 Enable Show Wi-Fi status in menu bar" >> "$auditfilelocation"
		echo "$(date -u)" "4.2 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "4.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore4_2 -bool false
	fi
fi

# 4.4 Ensure http server is not running 
# Verify organizational score
Audit4_4="$($Defaults read "$plistlocation" OrgScore4_4)"
# If organizational score is 1 or true, check status of client
# Code fragment from https://github.com/krispayne/CIS-Settings/blob/master/ElCapitan_CIS.sh
if [ "$Audit4_4" = "1" ]; then
	httpdDisabled="$(launchctl print-disabled system | /usr/bin/grep -c '"org.apache.httpd" => true')"
	if [ "$httpdDisabled" = 0 ]; then
		echo "* 4.4 Ensure http server is not running" >> "$auditfilelocation"
		echo "$(date -u)" "4.4 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "4.4 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore4_4 -bool false
	fi
fi

# 4.5 Ensure nfs server is not running
# Verify organizational score
Audit4_5="$($Defaults read "$plistlocation" OrgScore4_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit4_5" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -e /etc/exports  ]; then
		echo "4.5 Ensure nfs server is not running" >> "$auditfilelocation"
		echo "$(date -u)" "4.5 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "4.5 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore4_5 -bool false
	fi
fi

# 5.1.1 Secure Home Folders
# Verify organizational score
Audit5_1_1="$($Defaults read "$plistlocation" OrgScore5_1_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_1_1" = "1" ]; then
	homeFolders="$(find /Users -mindepth 1 -maxdepth 1 -type d -perm -1 | grep -v "Shared" | grep -v "Guest" | wc -l | xargs)"
	# If client fails, then note category in audit file
	if [ "$homeFolders" = "0" ]; then
		echo "$(date -u)" "5.1.1 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_1_1 -bool false; else
		echo "* 5.1.1 Secure Home Folders" >> "$auditfilelocation"
		echo "$(date -u)" "5.1.1 fix" | tee -a "$logFile"
	fi
fi

# 5.1.2 Check System Wide Applications for appropriate permissions
# Verify organizational score
Audit5_1_2="$($Defaults read "$plistlocation" OrgScore5_1_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_1_2" = "1" ]; then
	appPermissions="$(find /Applications -iname "*\.app" -type d -perm -2 -ls | wc -l | xargs)"
	# If client fails, then note category in audit file
	if [ "$appPermissions" = "0" ]; then
		echo "$(date -u)" "5.1.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_1_2 -bool false; else
		echo "* 5.1.2 Check System Wide Applications for appropriate permissions" >> "$auditfilelocation"
		echo "$(date -u)" "5.1.2 fix" | tee -a "$logFile"
	fi
fi

# 5.1.3 Check System folder for world writable files
# Verify organizational score
Audit5_1_3="$($Defaults read "$plistlocation" OrgScore5_1_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_1_3" = "1" ]; then
	sysPermissions="$(find  /System/Volumes/Data/System -type d -perm -2 -ls | grep -v "Public/Drop Box" | wc -l | xargs)"
	# If client fails, then note category in audit file
	if [ "$sysPermissions" = "0" ]; then
		echo "$(date -u)" "5.1.3 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_1_3 -bool false; else
		echo "* 5.1.3 Check System folder for world writable files" >> "$auditfilelocation"
		echo "$(date -u)" "5.1.3 fix" | tee -a "$logFile"
	fi
fi

# 5.1.4 Check Library folder for world writable files
# Verify organizational score
Audit5_1_4="$($Defaults read "$plistlocation" OrgScore5_1_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_1_4" = "1" ]; then
	libPermissions="$(find /Library -type d -perm -2 -ls | grep -v Caches | grep -v Adobe | grep -v VMware | grep -v "/Audio/Data" | wc -l | xargs)"
	# If client fails, then note category in audit file
	if [ "$libPermissions" = "0" ]; then
		echo "$(date -u)" "5.1.4 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_1_4 -bool false; else
		echo "* 5.1.4 Check Library folder for world writable files" >> "$auditfilelocation"
		echo "$(date -u)" "5.1.4 fix" | tee -a "$logFile"
	fi
fi

# 5.3 Reduce the sudo timeout period
# Verify organizational score
Audit5_3="$($Defaults read "$plistlocation" OrgScore5_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_3" = "1" ]; then
	sudoTimeout="$(cat /etc/sudoers | grep timestamp)"
	# If client fails, then note category in audit file
	if [ "$sudoTimeout" = "" ]; then
		echo "* 5.3 Reduce the sudo timeout period" >> "$auditfilelocation"
		echo "$(date -u)" "5.3 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "5.3 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_3 -bool false
	fi
fi


# 5.5 Automatically lock the login keychain for inactivity
# Verify organizational score
Audit5_4="$($Defaults read "$plistlocation" OrgScore5_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_4" = "1" ]; then
	keyTimeout="$(security show-keychain-info /Users/"$currentUser"/Library/Keychains/login.keychain 2>&1 | grep -c "no-timeout")"
	# If client fails, then note category in audit file
	if [ "$keyTimeout" -gt 0 ]; then
		echo "* 5.4 Automatically lock the login keychain for inactivity" >> "$auditfilelocation"
		echo "$(date -u)" "5.4 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "5.4 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_4 -bool false
	fi
fi

# 5.5 Use a separate timestamp for each user/tty combo
# Verify organizational score
Audit5_5="$($Defaults read "$plistlocation" OrgScore5_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_5" = "1" ]; then
	ttyTimestamp="$(cat /etc/sudoers | egrep tty_tickets)"
	# If client fails, then note category in audit file
	if [ "$ttyTimestamp" != "" ]; then
		echo "* 5.5 Use a separate timestamp for each user/tty combo" >> "$auditfilelocation"
		echo "$(date -u)" "5.5 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "5.5 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_5 -bool false
	fi
fi

# 5.6 Ensure login keychain is locked when the computer sleeps
# Verify organizational score
Audit5_6="$($Defaults read "$plistlocation" OrgScore5_6)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_6" = "1" ]; then
	lockSleep="$(security show-keychain-info /Users/"$currentUser"/Library/Keychains/login.keychain 2>&1 | grep -c "lock-on-sleep")"
	# If client fails, then note category in audit file
	if [ "$lockSleep" = 0 ]; then
		echo "* 5.6 Ensure login keychain is locked when the computer sleeps" >> "$auditfilelocation"
		echo "$(date -u)" "5.6 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "5.6 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_6 -bool false
	fi
fi

# 5.7 Do not enable the "root" account
# Verify organizational score
Audit5_7="$($Defaults read "$plistlocation" OrgScore5_7)"
if [ "$Audit5_7" = "1" ]; then
	#echo "$(date -u)" "Checking 5.7" | tee -a "$logFile"
	rootEnabled="$(dscl . -read /Users/root AuthenticationAuthority 2>&1 | grep -c "No such key")"
	rootEnabledRemediate="$(dscl . -read /Users/root UserShell 2>&1 | grep -c "/usr/bin/false")"
	if [ "$rootEnabled" = "1" ]; then
		echo "$(date -u)" "5.7 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_7 -bool false; elif
		[ "$rootEnabledRemediate" = "1" ]; then
		   echo "$(date -u)" "5.7 passed due to remediation" | tee -a "$logFile"
		   $Defaults write "$plistlocation" OrgScore5_7 -bool false
	else
	echo "* 5.7 Do Not enable the "root" account" >> "$auditfilelocation"
	echo "$(date -u)" "5.7 fix" | tee -a "$logFile"

	fi
fi

# 5.8 Disable automatic login
# Configuration Profile - LoginWindow payload > Options > Disable automatic login (checked)
# Verify organizational score
Audit5_8="$($Defaults read "$plistlocation" OrgScore5_8)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_8" = "1" ]; then
	CP_autologinEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'DisableAutoLoginClient')"
	# If client fails, then note category in audit file
	if [[ "$CP_autologinEnabled" -gt "0" ]] ; then
		echo "$(date -u)" "5.8 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_8 -bool false; else
		autologinEnabled="$($Defaults read /Library/Preferences/com.apple.loginwindow | grep -ow "autoLoginUser")"
		if [ "$autologinEnabled" = "" ]; then
			echo "$(date -u)" "5.8 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore5_8 -bool false; else
			echo "* 5.8 Disable automatic login" >> "$auditfilelocation"
			echo "$(date -u)" "5.8 fix" | tee -a "$logFile"
		fi
	fi
fi

# 5.9 Require a password to wake the computer from sleep or screen saver
# Configuration Profile - Security and Privacy payload > General > Require password * after sleep or screen saver begins (checked)
# Verify organizational score
Audit5_9="$($Defaults read "$plistlocation" OrgScore5_9)"
# If organizational score is 1 or true, check status of client
# If client fails, then note category in audit file
if [ "$Audit5_9" = "1" ]; then
	CP_screensaverPwd="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'askForPassword = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_screensaverPwd" -gt "0" ]] ; then
		echo "$(date -u)" "5.9 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_9 -bool false; else
		screensaverPwd="$($Defaults read /Users/"$currentUser"/Library/Preferences/com.apple.screensaver askForPassword)"
		if [ "$screensaverPwd" = "1" ]; then
			echo "$(date -u)" "5.9 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore5_9 -bool false; else
			echo "* 5.9 Require a password to wake the computer from sleep or screen saver" >> "$auditfilelocation"
			echo "$(date -u)" "5.9 fix" | tee -a "$logFile"
		fi
	fi
fi

# 5.10 Ensure system is set to hibernate and Destroy FileVault Key
# Verify organizational score
Audit5_10="$($Defaults read "$plistlocation" OrgScore5_10)"
# If client fails, then note category in audit file
if [ "$Audit5_10" = "1" ]; then
	macType=$(system_profiler SPHardwareDataType | egrep -c "Model Identifier: MacBook")
	if [[ "$macType" -ge 0 ]]; then
		hibernateValue=$(pmset -g | egrep standbydelaylow | awk '{print $2}')
		if [[ "$hibernateValue" == "" ]] || [[ "$hibernateValue" -gt 600 ]]; then
			echo "$(date -u)" "5.10 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore5_10 -bool false
		else
			echo "* 5.10 Ensure system is set to hibernate" >> "$auditfilelocation"
			echo "$(date -u)" "5.10 fix" | tee -a "$logFile"
		fi
	else
		echo "$(date -u)" "5.10 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_10 -bool false
	fi
fi

# 5.11 Require an administrator password to access system-wide preferences
# Verify organizational score
Audit5_11="$($Defaults read "$plistlocation" OrgScore5_11)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_11" = "1" ]; then
	adminSysPrefs="$(security authorizationdb read system.preferences 2> /dev/null | grep -A1 shared | grep -E '(true|false)' | grep -c "true")"
	# If client fails, then note category in audit file
	if [ "$adminSysPrefs" = "1" ]; then
		echo "* 5.11 Require an administrator password to access system-wide preferences" >> "$auditfilelocation"
		echo "$(date -u)" "5.11 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "5.11 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_11 -bool false
	fi
fi

# 5.12 Disable ability to login to another user's active and locked session
# Verify organizational score
Audit5_12="$($Defaults read "$plistlocation" OrgScore5_12)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_12" = "1" ]; then
	screensaverRules="$(/usr/bin/security authorizationdb read system.login.screensaver 2>&1 | grep -c 'use-login-window-ui')"
	# If client fails, then note category in audit file
	if [ "$screensaverRules" = "1" ]; then
		echo "$(date -u)" "5.12 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_12 -bool false
     else
		echo "* 5.12 Disable ability to login to another users active and locked session" >> "$auditfilelocation"
		echo "$(date -u)" "5.12 fix" | tee -a "$logFile"
	fi
fi

# 5.13 Create a custom message for the Login Screen
# Configuration Profile - LoginWindow payload > Window > Banner (message)
# Verify organizational score
Audit5_13="$($Defaults read "$plistlocation" OrgScore5_13)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_13" = "1" ]; then
	CP_loginMessage="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'LoginwindowText')"
	# If client fails, then note category in audit file
	if [[ "$CP_loginMessage" -gt "0" ]] ; then
		echo "$(date -u)" "5.13 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_13 -bool false; else
		loginMessage="$($Defaults read /Library/Preferences/com.apple.loginwindow.plist LoginwindowText)"
		if [[ $loginMessage = "" ]] || [[ $loginMessage = *"does not exist"* ]]; then
			echo "* 5.13 Create a custom message for the Login Screen" >> "$auditfilelocation"
			echo "$(date -u)" "5.13 fix" | tee -a "$logFile"; else
			echo "$(date -u)" "5.13 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore5_13 -bool false
		fi
	fi
fi

# 5.14 Create a Login window banner
# Policy Banner https://support.apple.com/en-us/HT202277
# Verify organizational score
Audit5_14="$($Defaults read "$plistlocation" OrgScore5_14)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_14" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -e /Library/Security/PolicyBanner.txt ] || [ -e /Library/Security/PolicyBanner.rtf ] || [ -e /Library/Security/PolicyBanner.rtfd ]; then
		echo "$(date -u)" "5.14 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_14 -bool false; else
		echo "* 5.14 Create a Login window banner" >> "$auditfilelocation"
		echo "$(date -u)" "5.14 fix" | tee -a "$logFile"
	fi
fi

# 5.16 Disable Fast User Switching (Not Scored)
# Configuration Profile - LoginWindow payload > Options > Enable Fast User Switching (unchecked)
# Verify organizational score
Audit5_16="$($Defaults read "$plistlocation" OrgScore5_16)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_16" = "1" ]; then
	CP_FastUserSwitching="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'MultipleSessionEnabled = 0')"
	# If client fails, then note category in audit file
	if [[ "$CP_FastUserSwitching" -gt "0" ]] ; then
		echo "$(date -u)" "5.16 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_16 -bool false; else
		FastUserSwitching="$($Defaults read /Library/Preferences/.GlobalPreferences MultipleSessionEnabled)"
		if [ "$FastUserSwitching" = "0" ]; then
			echo "$(date -u)" "5.16 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore5_16 -bool false; else
			echo "* 5.16 Disable Fast User Switching" >> "$auditfilelocation"
			echo "$(date -u)" "5.16 fix" | tee -a "$logFile"
		fi
	fi
fi

# 5.18 System Integrity Protection status
# Verify organizational score
Audit5_18="$($Defaults read "$plistlocation" OrgScore5_18)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_18" = "1" ]; then
	sipEnabled="$(/usr/bin/csrutil status | awk '{print $5}')"
	# If client fails, then note category in audit file
	if [ "$sipEnabled" = "enabled." ]; then
		echo "$(date -u)" "5.18 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_18 -bool false; else
		echo "* 5.18 System Integrity Protection status - not enabled" >> "$auditfilelocation"
		echo "$(date -u)" "5.18 fix" | tee -a "$logFile"
	fi
fi

# 5.19 Enable Sealed System Volume (SSV) 
# Verify organizational score
Audit5_19="$($Defaults read "$plistlocation" OrgScore5_19)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_19" = "1" ]; then
	ssvEnabled="$(/usr/bin/csrutil authenticated-root status | awk '{print $4}')"
	# If client fails, then note category in audit file
	if [ "$ssvEnabled" = "enabled" ]; then
		echo "$(date -u)" "5.19 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_19 -bool false; else
		echo "* 5.19 Enable Sealed System Volume (SSV) - not enabled" >> "$auditfilelocation"
		echo "$(date -u)" "5.19 fix" | tee -a "$logFile"
	fi
fi

# 5.20 Enable Library Validation 
# Verify organizational score
Audit5_19="$($Defaults read "$plistlocation" OrgScore5_20)"
# If organizational score is 1 or true, check status of client
if [ "$Audit5_20" = "1" ]; then
	libValidationDisabled="$($Defaults read /Library/Preferences/com.apple.security.librarayvalidation.plist DisableLibraryValidation)"
	# If client fails, then note category in audit file
	if [ "$libValidationDisabled" = 0 ]; then
		echo "$(date -u)" "5.20 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore5_20 -bool false; else
		echo "* 5.20 Library Validation - not enabled" >> "$auditfilelocation"
		echo "$(date -u)" "5.20 fix" | tee -a "$logFile"
	fi
fi

# 6.1.1 Display login window as name and password
# Configuration Profile - LoginWindow payload > Window > LOGIN PROMPT > Name and password text fields (selected)
# Verify organizational score
Audit6_1_1="$($Defaults read "$plistlocation" OrgScore6_1_1)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_1" = "1" ]; then
	CP_loginwindowFullName="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'SHOWFULLNAME = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_loginwindowFullName" -gt "0" ]] ; then
		echo "$(date -u)" "6.1.1 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_1_1 -bool false; else
		loginwindowFullName="$($Defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME)"
		if [ "$loginwindowFullName" != "1" ]; then
			echo "* 6.1.1 Display login window as name and password" >> "$auditfilelocation"
			echo "$(date -u)" "6.1.1 fix" | tee -a "$logFile"; else
			echo "$(date -u)" "6.1.1 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore6_1_1 -bool false
		fi
	fi
fi

# 6.1.2 Disable "Show password hints"
# Configuration Profile - LoginWindow payload > Options > Show password hint when needed and available (unchecked - Yes this is backwards)
# Verify organizational score
Audit6_1_2="$($Defaults read "$plistlocation" OrgScore6_1_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_2" = "1" ]; then
	CP_passwordHints="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'RetriesUntilHint = 0')"
	# If client fails, then note category in audit file
	if [[ "$CP_passwordHints" -gt "0" ]] ; then
		echo "$(date -u)" "6.1.2 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_1_2 -bool false; else
		passwordHints="$($Defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint)"
		if [ "$passwordHints" -gt 0 ] || [ "$passwordHints" = *exist* ]; then
			echo "* 6.1.2 Disable Show password hints" >> "$auditfilelocation"
			echo "$(date -u)" "6.1.2 fix" | tee -a "$logFile"; else
			echo "$(date -u)" "6.1.2 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore6_1_2 -bool false
		fi
	fi
fi

# 6.1.3 Disable guest account
# Configuration Profile - LoginWindow payload > Options > Allow Guest User (unchecked)
# Verify organizational score
Audit6_1_3="$($Defaults read "$plistlocation" OrgScore6_1_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_3" = "1" ]; then
	CP_guestEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'DisableGuestAccount = 1')"
	# If client fails, then note category in audit file
	if [[ "$CP_guestEnabled" -gt "0" ]] ; then
		echo "$(date -u)" "6.1.3 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_1_3 -bool false; else
		guestEnabled="$($Defaults read /Library/Preferences/com.apple.loginwindow.plist GuestEnabled)"
		if [ "$guestEnabled" = 1 ]; then
			echo "* 6.1.3 Disable guest account" >> "$auditfilelocation"
			echo "$(date -u)" "6.1.3 fix" | tee -a "$logFile"; else
			echo "$(date -u)" "6.1.3 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore6_1_3 -bool false
		fi
	fi
fi

# 6.1.4 Disable "Allow guests to connect to shared folders"
# Configuration Profile - 6.1.4 Disable Allow guests to connect to shared folders - Custom payload > com.apple.AppleFileServer guestAccess=false, com.apple.smb.server AllowGuestAccess=false
# Verify organizational score
Audit6_1_4="$($Defaults read "$plistlocation" OrgScore6_1_4)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_4" = "1" ]; then
	CP_afpGuestEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'guestAccess = 0')"
	CP_smbGuestEnabled="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'AllowGuestAccess = 0')"
	# If client fails, then note category in audit file
	if [[ "$CP_afpGuestEnabled" -gt "0" ]] || [[ "$CP_smbGuestEnabled" -gt "0" ]] ; then
		echo "$(date -u)" "6.1.4 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_1_4 -bool false; else
		afpGuestEnabled="$($Defaults read /Library/Preferences/com.apple.AppleFileServer guestAccess)"
		smbGuestEnabled="$($Defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess)"
		if [ "$afpGuestEnabled" = "1" ] || [ "$smbGuestEnabled" = "1" ]; then
			echo "* 6.1.4 Disable Allow guests to connect to shared folders" >> "$auditfilelocation"
			echo "$(date -u)" "6.1.4 fix" | tee -a "$logFile"
		else
			echo "$(date -u)" "6.1.4 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore6_1_4 -bool false
		fi
	fi
fi

# 6.1.5 Remove Guest home folder
# Verify organizational score
Audit6_1_5="$($Defaults read "$plistlocation" OrgScore6_1_5)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_1_5" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -e /Users/Guest ]; then
		echo "* 6.1.5 Remove Guest home folder" >> "$auditfilelocation"
		echo "$(date -u)" "6.1.5 fix" | tee -a "$logFile"; else
		echo "$(date -u)" "6.1.5 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_1_5 -bool false
	fi
fi

# 6.2 Turn on filename extensions
# Does not work as a Configuration Profile - .GlobalPreferences.plist
# Verify organizational score
Audit6_2="$($Defaults read "$plistlocation" OrgScore6_2)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_2" = "1" ]; then
		filenameExt="$($Defaults read /Users/"$currentUser"/Library/Preferences/.GlobalPreferences.plist AppleShowAllExtensions)"
	# If client fails, then note category in audit file
	if [ "$filenameExt" = "1" ]; then
		echo "$(date -u)" "6.2 passed" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_2 -bool false; else
		echo "* 6.2 Turn on filename extensions" >> "$auditfilelocation"
		echo "$(date -u)" "6.2 fix" | tee -a "$logFile"
	fi
fi

# 6.3 Disable the automatic run of safe files in Safari
# Configuration Profile - Custom payload > com.apple.Safari > AutoOpenSafeDownloads=false
# Verify organizational score
Audit6_3="$($Defaults read "$plistlocation" OrgScore6_3)"
# If organizational score is 1 or true, check status of client
if [ "$Audit6_3" = "1" ]; then
	CP_safariSafe="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'AutoOpenSafeDownloads = 0')"
	# If client fails, then note category in audit file
	if [[ "$CP_safariSafe" -gt "0" ]] ; then
		echo "$(date -u)" "6.3 passed cp" | tee -a "$logFile"
		$Defaults write "$plistlocation" OrgScore6_3 -bool false; else
		safariSafe="$(/usr/libexec/PlistBuddy -c "Print:AutoOpenSafeDownloads" /Users/"$currentUser"/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist)"
		if [[ "$safariSafe" = "true" ]]; then
			echo "* 6.3 Disable the automatic run of safe files in Safari" >> "$auditfilelocation"
			echo "$(date -u)" "6.3 fix" | tee -a "$logFile"; else
			echo "$(date -u)" "6.3 passed" | tee -a "$logFile"
			$Defaults write "$plistlocation" OrgScore6_3 -bool false
		fi
	fi
fi

echo "$(date -u)" "Audit complete" | tee -a "$logFile"
exit 0
