# Conditional Access Policies Documentation

This repository contains a comprehensive set of Microsoft Entra ID (Azure AD) Conditional Access policies designed to secure organizational access to cloud applications and resources.

PDF contains visual representation created by Conditional Access Documenter created by @Merril - https://idpowertoys.merill.net/ca

## Table of Contents

- [Overview](#overview)
- [Policy Categories](#policy-categories)
- [Policy Naming Convention](#policy-naming-convention)
- [Policy Inventory](#policy-inventory)
  - [Device Compliance Policies (CAD)](#device-compliance-policies-cad)
  - [Location-Based Policies (CAL)](#location-based-policies-cal)
  - [Protocol and Authentication Policies (CAP)](#protocol-and-authentication-policies-cap)
  - [User and Risk-Based Policies (CAU)](#user-and-risk-based-policies-cau)
- [Policy Structure](#policy-structure)
- [Deployment Guidelines](#deployment-guidelines)

---

## Overview

These Conditional Access policies provide a layered security approach to protect organizational resources by enforcing access controls based on:

- **Device platform and compliance status**
- **Geographic location and trusted networks**
- **Authentication protocols (prerequisite controls)**
- **User identity and risk levels**
- **Client application types**
- **Multi-factor authentication requirements**

All policies are exported in JSON format compatible with Microsoft Graph API for easy deployment and version control.

### Export Tool

These policies have been exported using the **IntuneManagement** tool by Micke-K, which can be found here:  
[https://github.com/Micke-K/IntuneManagement/](https://github.com/Micke-K/IntuneManagement/)

This PowerShell-based tool provides a comprehensive interface for managing and exporting Microsoft Intune and Entra ID configurations, including Conditional Access policies. The same tool can also be used to import these policies into your environment.

---

## Policy Categories

The policies are organized into four main categories:

| Prefix | Category | Description |
|--------|----------|-------------|
| **CAD** | Device-Related Policies | Policies that grant or restrict access based on device platform and compliance status |
| **CAL** | Location-Related Policies | Policies that control access based on geographic location and trusted networks |
| **CAP** | Prerequisite Policies | Foundational policies that block or allow specific authentication protocols and methods |
| **CAU** | User-Related Policies | Policies focused on user identity, MFA requirements, and risk-based conditions |

---

## Policy Naming Convention

Policy names follow a structured format for easy identification:

```
[PREFIX][NUMBER]-[SCOPE] [ACTION] [DESCRIPTION]-v[VERSION]
```

**Components:**
- **PREFIX**: Policy category (CAD, CAL, CAP, CAU)
- **NUMBER**: Sequential identifier (001-999)
- **SCOPE**: Target applications (O365, All, Selected, etc.)
- **ACTION**: Grant, Block, Session, or Require
- **DESCRIPTION**: Clear description of policy intent
- **VERSION**: Semantic version (v1.0, v1.1, etc.)

**Examples:**
- `CAD001-O365 Grant macOS access for All users when Modern Auth Clients and Compliant-v1.1`
- `CAU008-All Grant Require Phishing Resistant MFA for Admins when Browser and Modern Auth Clients-v1.4`

---

## Policy Inventory

### Device-Related Policies (CAD)

These policies enforce device compliance and platform-specific access controls.

| Policy ID | Name | Version | Status | Description |
|-----------|------|---------|--------|-------------|
| CAD001 | CAD001-O365 Grant macOS access for All users when Modern Auth Clients and Compliant | v1.1 | Must Have | Allows macOS devices to access Office 365 when compliant |
| CAD002 | CAD002-O365 Grant Windows access for All users when Modern Auth Clients and Compliant | v1.1 | Must Have | Allows Windows devices to access Office 365 when compliant |
| CAD003 | CAD003-O365 Grant iOS and Android access for All users when Modern Auth Clients and AppProPol or Compliant | v1.3 | Must Have | Allows mobile devices with app protection policy or compliance |
| CAD004 | CAD004-O365 Grant Require MFA for All users when Browser and Non-Compliant | v1.3 | Must Have | Requires MFA for browser access on non-compliant devices |
| CAD005 | CAD005-O365 Block access for unsupported device platforms for All users when Modern Auth Clients | v1.1 | Must Have | Blocks access from unsupported platforms |
| CAD006 | CAD006-O365 Session block download on unmanaged device for All users when Browser and Modern App Clients and Non-Compliant | v1.5 | Could Have | Prevents downloads on non-compliant devices |
| CAD007 | CAD007-O365 Session set Sign-in Frequency for Apps for All users when Modern Auth Clients and Non-Compliant | v1.2 | Could Have | Enforces re-authentication for non-compliant devices |
| CAD008 | CAD008-All Session set Sign-in Frequency for All users when Browser and Non-Compliant | v1.1 | Must Have | Enforces browser re-authentication frequency |
| CAD009 | CAD009-All Session disable browser persistence for All users when Browser and Non-Compliant | v1.2 | Must Have | Prevents persistent browser sessions on non-compliant devices |
| CAD010 | CAD010-RJD Require MFA for device join or registration when Browser and Modern Auth Clients | v1.1 | Must Have | Requires MFA for device registration actions |
| CAD011 | CAD011-O365 Grant Linux access for All users when Modern Auth Clients and Compliant | v1.0 | Must Have | Allows Linux devices to access Office 365 when compliant |
| CAD012 | CAD012-All Grant access for Admin users when Browser and Modern Auth Clients and Compliant | v1.1 | Could Have | Grants admin access with compliance requirement |
| CAD013 | CAD013-Selected Grant access for All users when Browser and Modern Auth Clients and Compliant | v1.0 | Could Have | General compliant device access policy |
| CAD014 | CAD014-O365 Require App Protection Policy for Edge on Windows for All users when Browser and Non-Compliant | v1.0 | Could Have | Enforces app protection for Edge browser |
| CAD015 | CAD015-All Grant access for All users when Browser and Modern Auth Clients and Compliant on Windows and macOS | v1.0 | Could Have | Platform-specific compliance policy |
| CAD016 | CAD016-EXO_SPO_CloudPC Require token protection when Modern Auth Clients on Windows | v1.2 | Could Have | Enforces token protection for Exchange, SharePoint, and Cloud PC |
| CAD017 | CAD017-Selected Grant iOS and Android access for All users when Modern Auth Clients and AppProPol or Compliant | v1.1 | Could Have | Mobile access with approved apps or compliance |
| CAD018 | CAD018-CloudPC Grant iOS and Android access for All users when Modern Auth Clients and AppProPol or Compliant | v1.0 | Could Have | Cloud PC mobile access policy |
| CAD019 | CAD019-Intune Require MFA and set sign-in frequency to every time | v1.0 | Must Have | Enforces MFA for Intune access with continuous authentication |

### Location-Related Policies (CAL)

These policies control access based on geographic location and trusted networks.

| Policy ID | Name | Version | Status | Description |
|-----------|------|---------|--------|-------------|
| CAL001 | CAL001-All Block specified locations for All users when Browser and Modern Auth Clients | v1.1 | Could Have | Blocks access from specified geographic locations |
| CAL002 | CAL002-RSI Require MFA registration from trusted locations only for All users when Browser and Modern Auth Clients | v1.4 | Could Have | Restricts security info registration to trusted locations |
| CAL003 | CAL003-All Block Access for Specified Service Accounts except from Provided Trusted Locations when Browser and Modern Auth Clients | v1.1 | Could Have | Limits service account access to trusted networks |
| CAL004 | CAL004-All Block access for Admins from non-trusted locations when Browser and Modern Auth Clients | v1.2 | Could Have | Prevents admin access from untrusted locations |
| CAL005 | CAL005-Selected Grant access for All users on less-trusted locations when Browser and Modern Auth Clients and Compliant | v1.0 | Could Have | Allows compliant device access from less-trusted locations |
| CAL006 | CAL006-All Only Allow Access from specified locations for specific accounts when Browser and Modern Auth Clients | v1.0 | Could Have | Restricts specific accounts to designated locations only |

### Prerequisite Policies (CAP)

These are foundational policies that manage authentication protocols and methods. They should be deployed first as prerequisites for other policies.

| Policy ID | Name | Version | Status | Description |
|-----------|------|---------|--------|-------------|
| CAP001 | CAP001-All Block Legacy Authentication for All users when OtherClients | v1.0 | Must Have | Blocks legacy authentication protocols |
| CAP002 | CAP002-All Block Exchange ActiveSync Clients for All users | v1.1 | Must Have | Blocks Exchange ActiveSync connections |
| CAP003 | CAP003-All Block device code authentication flow | v1.0 | Must Have | Prevents device code authentication method |
| CAP004 | CAP004-All Block authentication transfer | v1.0 | Must Have | Blocks authentication transfer flows |

### User-Related Policies (CAU)

These policies focus on user identity, MFA requirements, and risk-based access controls.

| Policy ID | Name | Version | Status | Description |
|-----------|------|---------|--------|-------------|
| CAU001 | CAU001-All Grant Require MFA for guests when Browser and Modern Auth Clients | v1.1 | Must Have | Requires MFA for guest user access |
| CAU001A | CAU001A-Windows Azure Active Directory Grant Require MFA for guests when Browser and Modern Auth Clients | v1.0 | Must Have | Requires MFA for Azure AD guest access |
| CAU002 | CAU002-All Grant Require MFA for All users when Browser and Modern Auth Clients | v1.5 | Must Have | Universal MFA requirement |
| CAU003 | CAU003-Selected Block unapproved apps for guests when Browser and Modern Auth Clients | v1.0 | Could Have | Restricts guest access to approved applications |
| CAU004 | CAU004-Selected Session route through MDCA for All users when Browser on Non-Compliant | v1.2 | Could Have | Routes non-compliant traffic through Microsoft Defender for Cloud Apps |
| CAU005 | CAU005-Selected Session route through MDCA for All users when Browser on Compliant | v1.1 | Could Have | Routes compliant traffic through MDCA for monitoring |
| CAU006 | CAU006-All Grant access for Medium and High Risk Sign-in for All Users when Browser and Modern Auth Clients require MFA | v1.4 | Could Have | Requires MFA for risky sign-ins |
| CAU007 | CAU007-All Grant access for Medium and High Risk Users for All Users when Browser and Modern Auth Clients require PWD reset | v1.3 | Could Have | Requires password reset for risky users |
| CAU008 | CAU008-All Grant Require Phishing Resistant MFA for Admins when Browser and Modern Auth Clients | v1.4 | Should Have | Enforces phishing-resistant MFA for administrators |
| CAU009 | CAU009-Management Grant Require MFA for Admin Portals for All Users when Browser and Modern Auth Clients | v1.2 | Must Have | Requires MFA for management portal access |
| CAU010 | CAU010-All Grant Require ToU for All Users when Browser and Modern Auth Clients | v1.2 | Could Have | Enforces Terms of Use acceptance |
| CAU011 | CAU011-All Block access for All users except licensed when Browser and Modern Auth Clients | v1.0 | Should Have (be carefull) | Restricts access to licensed users only |
| CAU012 | CAU012-RSI Combined Security Info Registration with TAP | v1.1 | Should Have | Security info registration with Temporary Access Pass |
| CAU013 | CAU013-All Grant Require phishing resistant MFA for All users when Browser and Modern Auth Clients | v1.0 | Should Have | Enforces phishing-resistant MFA for all users |
| CAU014 | CAU014-All Block Managed Identity when Sign in Risk is Medium or High | v1.0 | Must Have | Blocks managed identity access during risky sign-ins |
| CAU015 | CAU015-All Block access for High Risk Sign-in for All Users when Browser and Modern Auth Clients | v1.0 | Must Have | Blocks high-risk sign-in attempts |
| CAU016 | CAU016-All Block access for High Risk Users for All Users when Browser and Modern Auth Clients | v1.0 | Must Have | Blocks access for high-risk user accounts |
| CAU017 | CAU017-All Session set Sign-in Frequency for Admins when Browser | v1.0 | Must Have | Enforces frequent re-authentication for admins |
| CAU018 | CAU018-All Session disable browser persistence for Admins when Browser | v1.0 | Must Have | Prevents persistent sessions for admin accounts |
| CAU019 | CAU019-Selected Only allow approved apps for guests when Browser and Modern Auth Clients | v1.0 | Should Have | Restricts guest access to approved applications |

---

## Detailed Policy Notes

### Device-Related Policies (CAD)

#### CAD001 - Grant macOS access for All users when Modern Auth Clients and Compliant (v1.1)
Devices must be managed with Microsoft Intune and Compliance Policies should be assigned.

#### CAD002 - Grant Windows access for All users when Modern Auth Clients and Compliant (v1.1)
Devices must be managed with Microsoft Intune and Compliance Policies should be assigned.

#### CAD003 - Grant iOS and Android access for All users when Modern Auth Clients and AppProPol or Compliant (v1.3)
Either iOS or Android device must be managed using Microsoft Intune, with a compliance policy assigned, or the device is not managed (BYOD) and the app must be protected using an Intune App Protection Policy.

#### CAD004 - Grant Require MFA for All users when Browser and Non-Compliant (v1.3)
Requires MFA to access Office 365 when working on a browser on a non-compliant device. Note that we only allow browser access on non-compliant devices, which could be either managed or unmanaged.

#### CAD005 - Block access for unsupported device platforms for All users when Modern Auth Clients (v1.1)
Block all the platforms which are not covered by a Conditional Access policy.

#### CAD006 - Session block download on unmanaged device for All users when Browser and Modern App Clients and Non-Compliant (v1.5)
This prevents downloads from Office 365 on non-compliant devices. Users cannot download attachments, and cannot print attachments. In order for this to work you need to configure the mailbox policy, and SharePoint global settings. For SharePoint you can also define Purview Sensitivity Labels to provide more granular settings. See: https://www.vansurksum.com/2020/06/26/limit-access-to-outlook-web-access-and-sharepoint-online-and-onedrive-using-conditional-access-app-enforced-restrictions/ and https://www.vansurksum.com/2020/12/04/defining-more-granularity-for-your-conditional-access-app-enforced-restrictions-using-sensitivity-labels/

#### CAD007 - Session set Sign-in Frequency for Apps for All users when Modern Auth Clients and Non-Compliant (v1.2)
Sets the sign-in frequency to 7 days for non-compliant devices when using Modern Authentication Clients, which is basically for Apps installed on iOS and Android.

#### CAD008 - Session set Sign-in Frequency for All users when Browser and Non-Compliant (v1.1)
This sets the sign-in frequency of 1 day for the browser on non-compliant devices.

#### CAD009 - Session disable browser persistence for All users when Browser and Non-Compliant (v1.2)
This makes sure that when the browser is properly closed, the session cookies are removed as well.

#### CAD010 - Require MFA for device join or registration when Browser and Modern Auth Clients (v1.1)
Requires MFA when a device is either joined, or registered in Entra ID.

#### CAD011 - Grant Linux access for All users when Modern Auth Clients and Compliant (v1.0)
Even though there are no Modern Authentication Clients for Linux, this policy is there for consistency with macOS, iOS/iPadOS, Android and Windows policies.

#### CAD012 - Grant access for Admin users when Browser and Modern Auth Clients and Compliant (v1.1)
This optional policy is there if you only want admins to be able to access the environment coming from a compliant device. Keep in mind that in the browser the admin account must be signed-in for CA to recognize the compliance status of the device.

#### CAD013 - Grant access for All users when Browser and Modern Auth Clients and Compliant (v1.0)
Use this policy if you want to allow (some) users only access from a compliant device.

#### CAD014 - Require App Protection Policy for Edge on Windows for All users when Browser and Non-Compliant (v1.0)
Use this policy to enforce MAM for Windows (which is basically to force users to sign-in to the Edge Web browser). You can create an App Protection Policy to protect what can be done with the data in the browser session. You can also use the Edge Cloud Policy service to configure the security in that browser session on unmanaged devices.

#### CAD015 - Grant access for All users when Browser and Modern Auth Clients and Compliant on Windows and macOS (v1.0)
Only allow access when coming from a compliant Windows or macOS device.

#### CAD017 - Grant iOS and Android access for All users when Modern Auth Clients and AppProPol or Compliant (v1.1)
Make sure that defined resources can only be accessed from a compliant device or app protected using an app protection policy on iOS and Android.

#### CAD018 - Grant iOS and Android access for All users when Modern Auth Clients and AppProPol or Compliant (v1.0)
Only allow access to Cloud PC from iOS or Android device.

#### CAD019 - Require MFA and set sign-in frequency to every time (v1.0)
When registering device in Microsoft Intune, make sure that MFA is asked every time.

### Location-Related Policies (CAL)

#### CAL001 - Block specified locations for All users when Browser and Modern Auth Clients (v1.1)
Define the countries as locations you want to block so that users cannot work from these countries. There are many caveats with this policy since nowadays the internet breakout location can be very different from where the user actually is (VPN/eSIM etc.).

#### CAL002 - Require MFA registration from trusted locations only for All users when Browser and Modern Auth Clients (v1.4)
Only allow MFA to be registered from trusted locations. This is an optional policy.

#### CAL003 - Block Access for Specified Service Accounts except from Provided Trusted Locations when Browser and Modern Auth Clients (v1.1)
This policy is to make sure that non-personal accounts (service accounts) can only sign in from certain locations. In order for this to work, we also should exclude these accounts from the following policies: CAD002, CAD005, CAU002, CAU008, CAU009, CAU011, CAD012, CAL004, CAU011.

#### CAL004 - Block access for Admins from non-trusted locations when Browser and Modern Auth Clients (v1.2)
Optional policy, to use if you want admins only to be able to access the environment from specified locations.

#### CAL005 - Grant access for All users on less-trusted locations when Browser and Modern Auth Clients and Compliant (v1.0)
Define your less trusted countries as a location, so that when applicable users can only work on compliant devices while in that country.

#### CAL006 - Only Allow Access from specified locations for specific accounts when Browser and Modern Auth Clients (v1.0)
Restricts specific accounts to designated locations only.

### Prerequisite Policies (CAP)

#### CAP001 - Block Legacy Authentication for All users when OtherClients (v1.0)
Make sure that legacy authentication is fully blocked. Legacy authentication is capable of bypassing Conditional Access.

#### CAP002 - Block Exchange ActiveSync Clients for All users (v1.1)
Make sure that Exchange ActiveSync is blocked.

#### CAP003 - Block device code authentication flow (v1.0)
Block device code authentication. When temporarily needed (for example to register Teams Rooms devices) add user doing the registration to the exclude group.

#### CAP004 - Block authentication transfer (v1.0)
Block authentication transfer. When needed add user to exclude group.

### User-Related Policies (CAU)

#### CAU001 - Grant Require MFA for guests when Browser and Modern Auth Clients (v1.1)
Require MFA for guest users for All Resources except for the Microsoft Rights Management resource. See blog from Tony Redmond: https://office365itpros.com/2024/02/12/conditional-access-mfa-email/

#### CAU001A - Grant Require MFA for guests when Browser and Modern Auth Clients (Azure AD specific) (v1.0)
Because we exclude one app in CAU001, we must protect Azure Active Directory resource per recommendation from Microsoft. See: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#conditional-access-behavior-when-an-all-resources-policy-has-an-app-exclusion

#### CAU002 - Grant Require MFA for All users when Browser and Modern Auth Clients (v1.5)
Require MFA for all users for all resources, guests excluded. In the past there used to be exclusions here for accessing the Windows Store so that devices could receive licenses, but this issue has been fixed by Microsoft.

#### CAU003 - Block unapproved apps for guests when Browser and Modern Auth Clients (v1.0)
In this policy you can define the apps which you don't want guest users to access. You can also do it the other way around, then you need to configure CAU019. Please read the following blog post for more information: https://www.vansurksum.com/2025/10/12/configuring-conditional-access-for-guest-users-allowing-only-office-365-and-essential-apps/

#### CAU004 - Session route through MDCA for All users when Browser on Non-Compliant (v1.2)
Make sure that selected apps are sent to Microsoft Defender for Cloud Apps, so that we can configure policies for them.

#### CAU005 - Session route through MDCA for All users when Browser on Compliant (v1.1)
Configure apps which must be monitored by Microsoft Defender for Cloud Apps on compliant devices.

#### CAU006 - Grant access for Medium and High Risk Sign-in for All Users when Browser and Modern Auth Clients require MFA (v1.4)
When medium or high risk is detected, this is a direct copy of the default identity protection policy. High risk sign-ins must be blocked nowadays so also configure CAU015.

#### CAU007 - Grant access for Medium and High Risk Users for All Users when Browser and Modern Auth Clients require PWD reset (v1.3)
When medium or high risk is detected, this is a direct copy of the default identity protection policy. High risk users must be blocked nowadays so also configure CAU016. This policy excludes guest users (per recommendation from Microsoft) since user risk is coming from their tenant and we cannot dismiss that.

#### CAU008 - Grant Require Phishing Resistant MFA for Admins when Browser and Modern Auth Clients (v1.4)
Today, this is a must have policy. Make sure that Administrators have phishing resistant MFA configured before enabling though. Roll out new Administrators using TAP.

#### CAU009 - Grant Require MFA for Admin Portals for All Users when Browser and Modern Auth Clients (v1.2)
Requires MFA for management portal access.

#### CAU010 - Grant Require ToU for All Users when Browser and Modern Auth Clients (v1.2)
Has exclusions for Intune Enrollment (since not supported).

#### CAU011 - Block access for All users except licensed when Browser and Modern Auth Clients (v1.0)
Be very careful with this policy. Make sure that you first identify all your legit users/personas and exclude them first before enabling this policy.

#### CAU012 - Combined Security Info Registration with TAP (v1.1)
This should be the default method for users to register phishing resistant MFA, like FIDO2 or passkeys in the Authenticator app.

#### CAU013 - Grant Require phishing resistant MFA for All users when Browser and Modern Auth Clients (v1.0)
This policy should eventually replace CAU002, once all your users have phishing resistant MFA configured.

#### CAU014 - Block Managed Identity when Sign in Risk is Medium or High (v1.0)
Make sure that you have at least one Workload Identity license in your tenant to properly import this policy. Blocks access when risk is medium or high. You should include all your service principals having risky rights in the environment.

#### CAU015 - Block access for High Risk Sign-in for All Users when Browser and Modern Auth Clients (v1.0)
Indeed, with the current phishing using AiTM (Adversary-in-the-Middle) this is becoming a must have.

#### CAU016 - Block access for High Risk Users for All Users when Browser and Modern Auth Clients (v1.0)
Same remark as CAU015 - with current phishing using AiTM this is becoming a must have.

#### CAU017 - Session set Sign-in Frequency for Admins when Browser (v1.0)
Make sure that Admin browser sessions have a sign-in frequency. Configure the sign-in frequency in harmony with things like PIM etc.

#### CAU018 - Session disable browser persistence for Admins when Browser (v1.0)
Make sure that browser sessions are non-persistent.

#### CAU019 - Only allow approved apps for guests when Browser and Modern Auth Clients (v1.0)
This policy could replace the CAU003 policy, only allowing access to Office 365 and other services needed for guest users. See also: https://www.vansurksum.com/2025/10/12/configuring-conditional-access-for-guest-users-allowing-only-office-365-and-essential-apps/

---

## Policy Structure

Each policy JSON file contains the following key components:

### Core Properties
- **displayName**: Human-readable policy name
- **state**: Policy status (enabled/disabled/enabledForReportingButNotEnforced)
- **createdDateTime**: Policy creation timestamp
- **modifiedDateTime**: Last modification timestamp

### Conditions
Defines when the policy applies:

- **users**: Target users, groups, roles, and external users
- **applications**: Target cloud apps and user actions
- **clientAppTypes**: Browser, mobile apps, desktop clients, etc.
- **platforms**: Device platforms (Windows, macOS, iOS, Android, Linux)
- **locations**: Named locations and IP ranges
- **devices**: Device filter rules and compliance requirements
- **signInRiskLevels**: Low, medium, high risk levels
- **userRiskLevels**: User risk assessment levels

### Controls
Defines what happens when conditions are met:

#### Grant Controls
- **mfa**: Require multi-factor authentication
- **compliantDevice**: Require device compliance
- **domainJoinedDevice**: Require hybrid Azure AD joined device
- **approvedApplication**: Require approved client app
- **appProtectionPolicy**: Require app protection policy
- **passwordChange**: Require password change
- **authenticationStrength**: Custom authentication strength policies

#### Session Controls
- **applicationEnforcedRestrictions**: Enforce app-based restrictions
- **cloudAppSecurity**: Use Conditional Access App Control
- **signInFrequency**: Control sign-in frequency
- **persistentBrowser**: Control browser session persistence

---

## Deployment Guidelines

### Prerequisites
1. Microsoft Entra ID P1 or P2 license
2. Global Administrator or Conditional Access Administrator role
3. Microsoft Graph API access (for automated deployment)

### Deployment Methods

#### Option 1: IntuneManagement Tool (Recommended)
The easiest method is to use the same IntuneManagement tool that was used to export these policies:

1. Download and launch the [IntuneManagement tool](https://github.com/Micke-K/IntuneManagement/)
2. Connect to your tenant
3. Navigate to **Conditional Access** > **Import**
4. Select the JSON files to import
5. Review settings and configure exclusions
6. Import the policies

This method provides a user-friendly interface and handles policy dependencies automatically.

#### Option 2: Azure Portal (Manual)
1. Navigate to **Azure AD > Security > Conditional Access**
2. Click **New policy** > **Create policy from JSON**
3. Upload the JSON file
4. Review settings and exclusions
5. Set to **Report-only mode** initially
6. Monitor impact before enabling

#### Option 3: Microsoft Graph API (Automated)
```powershell
# Import policy using Microsoft Graph
$policyJson = Get-Content -Path "CAD001-O365 Grant macOS access for All users when Modern Auth Clients and Compliant-v1.1.json" | ConvertFrom-Json
Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Body ($policyJson | ConvertTo-Json -Depth 10)
```

#### Option 4: PowerShell with Microsoft Graph SDK
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Import all policies
$policies = Get-ChildItem -Path ".\ConditionalAccess" -Filter "*.json"
foreach ($policy in $policies) {
    $json = Get-Content -Path $policy.FullName -Raw | ConvertFrom-Json
    New-MgIdentityConditionalAccessPolicy -BodyParameter $json
}
```

### Best Practices

1. **Test in Report-Only Mode**
   - Deploy policies in report-only mode first
   - Monitor sign-in logs for 7-14 days
   - Identify potential user impact

2. **Configure Exclusions**
   - Create break-glass admin accounts
   - Exclude emergency access accounts from all policies
   - Document all exclusion groups

3. **Phased Rollout**
   - Start with pilot groups
   - Gradually expand to broader user base
   - Monitor helpdesk tickets and user feedback

4. **Regular Review**
   - Review policies quarterly
   - Update exclusion groups as needed
   - Adjust based on security incidents

5. **Documentation**
   - Maintain change log for policy modifications
   - Document business justification for each policy
   - Keep exclusion group membership documented

### Important Notes

- **Group IDs**: Update excluded group GUIDs before deployment to match your environment
- **Named Locations**: Configure named locations before deploying location-based policies
- **Authentication Strengths**: Create custom authentication strength policies if referenced
- **App Protection Policies**: Ensure Intune app protection policies are configured
- **Compliance Policies**: Configure device compliance policies before deploying device-based CA

---

## Support and Maintenance

### Version Control
- Policy versions follow semantic versioning (MAJOR.MINOR)
- Version increments indicate policy changes
- Review change history in commit logs

### Monitoring
Monitor policy effectiveness using:
- **Azure AD Sign-in Logs**: Review applied policies and results
- **Conditional Access Insights**: Built-in reporting
- **Azure Monitor**: Advanced analytics and alerting
- **Microsoft Sentinel**: Security information and event management

### Troubleshooting
Common issues and solutions:
- **Users locked out**: Check exclusion groups and break-glass accounts
- **Policy not applying**: Verify user/group scope and conditions
- **MFA not triggered**: Review authentication strength settings
- **Compliant devices blocked**: Check device compliance status in Intune

---

## Contributing

When modifying or adding policies:
1. Update the version number in the policy name
2. Document changes in commit messages
3. Update this README with new policies
4. Test thoroughly in non-production environment

---

## License

These policies are provided as-is for reference and adaptation to your organizational needs. Review and modify according to your security requirements.

---

## Additional Resources

- [Microsoft Conditional Access Documentation](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/)
- [Conditional Access Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/best-practices)
- [Microsoft Graph API Reference](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy)
- [Zero Trust Security Model](https://learn.microsoft.com/en-us/security/zero-trust/)

---

**Last Updated**: October 2025  
**Total Policies**: 48  
**Policy Categories**: 4 (CAD, CAL, CAP, CAU)



