# Azure CIS Benchmark
This InSpec Profile was created to facilitate testing and auditing of `CIS Azure Benchmark`
infrastructure and applications when validating compliancy with [Center for Internet Security (CIS) Benchmark](https://www.cisecurity.org/cis-benchmarks)
requirements.
 
- Profile Version: **3.0.0**
- Benchmark Date: **2024-09-05**
- Benchmark Version: **3.0.0**
 
 
This profile was developed to reduce the time it takes to perform a security check based upon the
CIS Guidance from the Center for Internet Security (CIS).
 
The CIS Azure Foundation CIS Profile uses the [InSpec](https://github.com/inspec/inspec)
open-source compliance validation language to support automation of the required compliance, security
and policy testing for Assessment and Authorization (A&A) and Authority to Operate (ATO) decisions
and Continuous Authority to Operate (cATO) processes.

The Azure CIS Benchmark includes security requirements for a Azure environment.
 
Table of Contents
=================
* [CIS Benchmark  Information](#benchmark-information)
* [Requirements](#requirements)
* [Getting Started](#getting-started)
    * [Intended Usage](#intended-usage)
    * [Tailoring to Your Environment](#tailoring-to-your-environment)
    * [Testing the Profile Controls](#testing-the-profile-controls)
* [Running the Profile](#running-the-profile)
    * [Directly from Github](#directly-from-github)
    * [Different Run Options](#different-run-options)
* [Using Heimdall for Viewing Test Results](#using-heimdall-for-viewing-test-results)
* [Check Overview](#check-overview)
 
## Benchmark Information
The Center for Internet Security, Inc. (CIS®) create and maintains a set of Critical Security Controls (CIS Controls) for applications, computer systems and networks.

The original benchmark document that serves as the basis for this automated testing profile can be found at the [CIS Workbench](https://workbench.cisecurity.org) website.
 
[top](#table-of-contents)

## Requirements
### Azure Credentials
Your Azure admin may need to be contacted to obtain some of these credentials. The following credentials are needed, as highlighted by the [train-pwsh](https://github.com/mitre/train-pwsh) documentation:
- client_id (id of client)
- tenant_id (id of tenant)
- client_secret (secret key for client)
- certificate_path (path on machine where authentication certificate is stored)
- certificate_password (password for certificate)
- organization (organization domain)
- sharepoint_admin_url (sharepoint url for admin)
- pwsh_path (path on machine where the PowerShell executable is stored)

Some details to create credentials if you are a Azure admin:
- Create an application registration within your account, which will provide you with the appropriate credentials to login such as Client ID and Tenant ID. You will need to create a Client Secret/Certificate as well. The following link provides more detail on how to setup an application registration: [Application_Registration_Steps](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=certificate)


### Ensure the Following Permissions on your Application Registration Account
  Request your Azure admin for these permissions to Azure modules or enable these permissions if you are the admin:
  - Microsoft Graph
    - SecurityEvents.Read.All
    - User.Read
    - UserAuthenticationMethod.Read.All
    - AuditLog.Read.All,
    - Policy.Read.All
  - Office 365 Exchange Online
    - Exchange.ManageAsApp
  - SharePoint
    - Sites.FullControl.All

### Required software and steps needed on the InSpec Runner
- git
- [PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-7.4)
- [InSpec](https://www.chef.io/products/chef-inspec/)
- [train-pwsh](https://github.com/mitre/train-pwsh)
- [inspec-pwsh](https://github.com/mitre/inspec-pwsh)

Inspec, train-pwsh, inspec-pwsh are already included as gems in this profile and should not need separate downloads. The profile just needs to be ran with bundle exec to ensure the gems are loaded.  

It is also important to follow/understand the documentation for train-pwsh and inspec-pwsh that is linked above for this profile to run correctly. For context, the train-pwsh is the transport that is used to maintain a persistent connection with various PowerShell sessions. Meanwhile, inspec-pwsh is a resource pack that is used to connect controls using different modules to its corresponding session group (e.g. session for exchange, teams, exchange/graph, etc.). The documentation for inspec-pwsh has more detail about the resource pack. 

Additionally, for train-pwsh, the organization field will also need to be defined as a environment variable named `ORGANIZATION` as it is used in a profile. The train-pwsh documentation has more detail on how to create this environment variable. Additionally, it is important to note that train-pwsh is not being invoked using code in this profile, so the config.json file approach needs to be followed for train to run correctly. The documentation for train-pwsh goes into more detail on how to create the config.json and  populate its contents with your Azure credentials that are used by this profile. 

### PowerShell Module Installation
Ensure access and install the following PowerShell modules. The controls also have the module installation code when running the PowerShell queries for redundancy purposes:
- [Microsoft.Graph](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0#installation)
- [ExchangeOnlineManagement](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps)
- [PnP.PowerShell](https://learn.microsoft.com/en-us/powershell/sharepoint/sharepoint-pnp/sharepoint-pnp-cmdlets)
- [MicrosoftTeams](https://learn.microsoft.com/en-us/microsoftteams/teams-powershell-install)

### Test O365 Example

Upon obtaining the right permissions/credentials and downloading the correct modules/software, test that these permissions work by running the o365_example_baseline profile available at the following link: [O365 Profile](https://github.com/mitre/o365_example_baseline). If the o365 profile runs correctly, then this profile should be able to ran correctly. The o365_example_baseline profile contains a subset of controls from this profile, and also leverages `train-pwsh` and `inspec-pwsh`. It should serve as a good test to ensure that `train-pwsh` and `inspec-pwsh` are working properly. 

More details on how to use `train-pwsh` and `inspec-pwsh` are detailed below:

- [train-pwsh](https://github.com/mitre/train-pwsh)
- [inspec-pwsh](https://github.com/mitre/inspec-pwsh)

## Getting Started  
### InSpec (CINC Auditor) setup
For maximum flexibility/accessibility, CINC Auditor (`cinc-auditor`) is the executable program that should be used to run this testing profile.

CINC Auditor is the open-source packaged binary version of Chef InSpec,
compiled by the CINC (CINC Is Not Chef) project in coordination with Chef using Chef's always-open-source InSpec source code. CINC Auditor and InSpec are built from the same source code and function identically, but CINC Auditor requires no license to use (which means it also does not come with any expectation of support from Chef).

For more information see [CINC Home](https://cinc.sh/)
 
It is intended and recommended that CINC Auditor and this profile executed from a __"runner"__ host
(such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop)
against the target. This can be any Unix/Linux/MacOS or Windows runner host, with access to the Internet.
 
> [!TIP]
> **For the best security of the runner, always install on the runner the latest version of CINC Auditor and any other supporting language components.**
 
To install CINC Auditor on a UNIX/Linux/MacOS platform use the following command:
```bash
curl -L https://omnitruck.cinc.sh/install.sh | sudo bash -s -- -P cinc-auditor
```
 
To install CINC Auditor on a Windows platform (PowerShell) use the following command:
```powershell
. { iwr -useb https://omnitruck.cinc.sh/install.ps1 } | iex; install -project cinc-auditor
```
 
To confirm successful install of CINC Auditor:
```
cinc-auditor -v
```
 
Latest versions and other installation options are available at [CINC Auditor](https://cinc.sh/start/auditor/)'s website.
 
[top](#table-of-contents)
### Intended Usage
1. The latest `released` version of the profile is intended for use in A&A testing, as well as
    providing formal results to Authorizing Officials and Identity and Access Management (IAM)s.
    Please use the `released` versions of the profile in these types of workflows.
 
2. The `main` branch is a development branch that will become the next release of the profile.
    The `main` branch is intended for use in _developing and testing_ merge requests for the next
    release of the profile, and _is not intended_ be used for formal and ongoing testing on systems.
 
[top](#table-of-contents)
### Tailoring to Your Environment
This profile uses InSpec Inputs to provide flexibility during testing. Inputs allow for
customizing the behavior of Chef InSpec profiles.
 
InSpec Inputs are defined in the `inspec.yml` file. The `inputs` configured in this
file are **profile definitions and defaults for the profile** extracted from the profile
guidances and contain metadata that describe the profile, and shouldn't be modified.
 
InSpec provides several methods for customizing profile behaviors at run-time that does not require
modifying the `inspec.yml` file itself (see [Using Customized Inputs](#using-customized-inputs)).
 
The following inputs are permitted to be configured in an inputs `.yml` file (often named inputs.yml)
for the profile to run correctly on a specific environment, while still complying with the security
guidance document intent. This is important to prevent confusion when test results are passed downstream
to different stakeholders under the *security guidance name used by this profile repository*
 
For changes beyond the inputs cited in this section, users can create an *organizationally-named overlay repository*.
For more information on developing overlays, reference the [MITRE SAF Training](https://mitre-saf-training.netlify.app/courses/beginner/10.html)
 
#### Example of tailoring Inputs *While Still Complying* with the security guidance document for the profile:
 
```yaml
```
 
> [!NOTE]
>Inputs are variables that are referenced by control(s) in the profile that implement them.
 They are declared (defined) and given a default value in the `inspec.yml` file.
 
#### Using Customized Inputs
Customized inputs may be used at the CLI by providing an input file or a flag at execution time.
 
1. Using the `--input` flag
 
    Example: `[inspec or cinc-auditor] exec <my-profile.tar.gz> --input disable_slow_controls=true`
 
2. Using the `--input-file` flag.
   
    Example: `[inspec or cinc-auditor] exec <my-profile.tar.gz> --input-file=<my_inputs_file.yml>`
 
>[!TIP]
> For additional information about `input` file examples reference the [MITRE SAF Training](https://mitre.github.io/saf-training/courses/beginner/06.html#input-file-example)
 
Chef InSpec Resources:
- [InSpec Profile Documentation](https://docs.chef.io/inspec/profiles/).
- [InSpec Inputs](https://docs.chef.io/inspec/profiles/inputs/).
- [inspec.yml](https://docs.chef.io/inspec/profiles/inspec_yml/).
 
 
[top](#table-of-contents)
### Testing the Profile Controls
The Gemfile provided contains all the necessary ruby dependencies for checking the profile controls.
#### Requirements
All action are conducted using `ruby` (gemstone/programming language). Currently `inspec`
commands have been tested with ruby version 3.1.2. A higher version of ruby is not guaranteed to
provide the expected results. Any modern distribution of Ruby comes with Bundler preinstalled by default.
 
Install ruby based on the OS being used, see [Installing Ruby](https://www.ruby-lang.org/en/documentation/installation/)
 
After installing `ruby` install the necessary dependencies by invoking the bundler command
(must be in the same directory where the Gemfile is located):
```bash
bundle install
```
 
#### Testing Commands
 
Linting and validating controls:
```bash
  bundle exec rake [inspec or cinc-auditor]:check # Validate the InSpec Profile
  bundle exec rake lint                            # Run RuboCop Linter
  bundle exec rake lint:auto_correct       # Autocorrect RuboCop offenses (only when it's safe)
  bundle exec rake pre_commit_checks  # Pre-commit checks
```
 
Ensure the controls are ready to be committed into the repo:
```bash
  bundle exec rake pre_commit_checks
```
 
 
[top](#table-of-contents)
## Running the Profile
**Note**: Replace the profile's directory name - e.g. - `<Profile>` with `.` if currently in the profile's root directory.
**Note 2**: The `<Name of Dictionary Storing Pwsh Options>` will be `pwsh-options` if exactly following train-pwsh documentation.
```sh
bundle exec cinc-auditor exec <Profile> -t pwsh://<Name of Dictionary Storing Pwsh Options> --controls=<control_id> --enhanced-outcomes --input-file=inputs.yml
```

#### Execute a Single Control and save results as JSON 
```sh
bundle exec cinc-auditor exec <Profile> -t pwsh://<Name of Dictionary Storing Pwsh Options>> --controls=<control_id> --enhanced-outcomes --input-file=inputs.yml --reporter json:results.json
```

#### Execute All Controls in the Profile 
```sh
bundle exec cinc-auditor exec <Profile> -t pwsh://<Name of Dictionary Storing Pwsh Options>> --enhanced-outcomes --input-file=inputs.yml
```

#### Execute all the Controls in the Profile and save results as JSON 
```sh
bundle exec cinc-auditor exec <Profile> -t pwsh://<Name of Dictionary Storing Pwsh Options>> --enhanced-outcomes --input-file=inputs.yml --reporter json:results.json
```
[top](#table-of-contents)

## Different Run Options
 
[Full exec options](https://docs.chef.io/inspec/cli/#options-3)
 
[top](#table-of-contents)

## Using Heimdall for Viewing Test Results
The JSON results output file can be loaded into **[Heimdall-Lite](https://heimdall-lite.mitre.org/)**
or **[Heimdall-Server](https://github.com/mitre/heimdall2)** for a user-interactive, graphical view of the profile scan results.
 
Heimdall-Lite is a `browser only` viewer that allows you to easily view your results directly and locally rendered in your browser.
Heimdall-Server is configured with a `data-services backend` allowing for data persistency to a database (PostgreSQL).
For more detail on feature capabilities see [Heimdall Features](https://github.com/mitre/heimdall2?tab=readme-ov-file#features)
 
Heimdall can **_export your results into a DISA Checklist (CKL) file_** for easily uploading into eMass using the `Heimdall Export` function.
 
Depending on your environment restrictions, the [SAF CLI](https://saf-cli.mitre.org) can be used to run a local docker instance
of Heimdall-Lite via the `saf view:heimdall` command.
 
Additionally both Heimdall applications can be deployed via docker, kubernetes, or the installation packages.
## Check Overview

### Azure Services

This profile evaluates the Azure CIS Benchmark compliance of the following Azure administrative centers by evaluating their setting configurations:

- Azure Admin Center
- Azure Defender
- Microsoft Purview
- Microsoft Entra Admin Center
- Microsoft Exchange Admin Center
- Microsoft SharePoint Admin Center
- Microsoft Fabric

### Control and Automation Status

Not all controls in the CIS Benchmark are capable of automated assessment. The table below marks which controls are automated and which ones are manual.

| Number | Description | Implemented | Implementation Method | Notes |
|---------|-------------|-------------|---------------------|-------|
| - | Benchmark | Automatable | Implementation | - |
| 1 | Identity and Access Management | - | - | - |
| 1.1 | Security Defaults | - | - | - |
| 1.1.1 | Ensure Security Defaults is enabled on Microsoft Entra ID (Manual) | No | - | - |
| 1.1.2 | Ensure that Multi-Factor Auth Status is Enabled for all Privileged Users (Manual) | Half | REST API to audit | - |
| 1.1.3 | Ensure that Multi-Factor Auth Status is Enabled for all Non-Privileged Users (Manual) | Half | REST API to audit | - |
| 1.1.4 | Ensure that Allow users to remember multi-factor authentication on devices they trust is Disabled (Manual) | No | - | - |
| 1.2 | Conditional Access | - | - | - |
| 1.2.1 | Ensure Trusted Locations Are Defined (Manual) | Yes | Powershell | - |
| 1.2.2 | Ensure that an exclusionary Geographic Access Policy is considered (Manual) | Yes | Powershell | - |
| 1.2.3 | Ensure that A Multi-factor Authentication Policy Exists for Administrative Groups (Manual) | No | - | - |
| 1.2.4 | Ensure that A Multi-factor Authentication Policy Exists for All Users (Manual) | No | - | - |
| 1.2.5 | Ensure Multi-factor Authentication is Required for Risky Sign-ins (Manual) | No | - | - |
| 1.2.6 | Ensure Multifactor Authentication is Required for Windows Azure Service Management API (Manual) | No | - | - |
| 1.2.7 | Ensure Multifactor Authentication is Required to access Microsoft Admin Portals (Manual) | No | - | - |
| 1.3 | Ensure that Restrict non-admin users from creating tenants is set to Yes (Manual) | Yes | Powershell | - |
| 1.4 | Ensure Guest Users Are Reviewed on a Regular Basis (Manual) | Yes | Azure CLI | - |
| 1.5 | Ensure That Number of methods required to reset is set to 2 (Manual) | No | - | - |
| 1.6 | Ensure that a Custom Bad Password List is set to Enforce for your Organization (Manual) | No | - | - |
| 1.7 | Ensure that Number of days before users are asked to re-confirm their authentication information is not set to 0 (Manual) | No | - | - |
| 1.8 | Ensure that Notify users on password resets? is set to Yes (Manual) | No | - | - |
| 1.9 | Ensure That Notify all admins when other admins reset their password? is set to Yes (Manual) | No | - | - |
| 1.10 | Ensure User consent for applications is set to Do not allow user consent (Manual) | Half | Powershell to audit | - |
| 1.11 | Ensure User consent for applications Is Set To Allow for Verified Publishers (Manual) | Yes | Powershell | - |
| 1.12 | Ensure that Users can add gallery apps to My Apps is set to No (Manual) | No | - | - |
| 1.13 | Ensure That Users Can Register Applications Is Set to No (Manual) | Yes | Powershell | - |
| 1.14 | Ensure That Guest users access restrictions is set to Guest user access is restricted to properties and memberships of their own directory objects (Manual) | Half | Powershell to audit | - |
| 1.15 | Ensure that Guest invite restrictions is set to Only users assigned to specific admin roles can invite guest users (Manual) | No | - | - |
| 1.16 | Ensure That Restrict access to Microsoft Entra admin center is Set to Yes (Manual) | No | - | - |
| 1.17 | Ensure that Restrict user ability to access groups features in the Access Pane is Set to Yes (Manual) | No | - | - |
| 1.18 | Ensure that Users can create security groups in Azure portals, API or PowerShell is set to No (Manual) | No | - | - |
| 1.19 | Ensure that Owners can manage group membership requests in the Access Panel is set to No (Manual) | No | - | - |
| 1.20 | Ensure that Users can create Microsoft 365 groups in Azure portals, API or PowerShell is set to No (Manual) | No | - | - |
| 1.21 | Ensure that Require Multi-Factor Authentication to register or join devices with Microsoft Entra ID is set to Yes (Manual) | No | - | - |
| 1.22 | Ensure That No Custom Subscription Administrator Roles Exist (Automated) | Yes | Azure CLI | - |
| 1.23 | Ensure a Custom Role is Assigned Permissions for Administering Resource Locks (Manual) | Half | Powershell to remediate | - |
| 1.24 | Ensure That Subscription leaving Microsoft Entra ID directory and Subscription entering Microsoft Entra ID directory Is Set To Permit No One (Manual) | No | - | - |
| 1.25 | Ensure fewer than 5 users have global administrator assignment (Manual) | No | - | - |
| 2 | Microsoft Defender | - | - | - |
| 2.1 | Microsoft Defender for Cloud | - | - | - |
| 2.1.1 | Ensure That Microsoft Defender for Servers Is Set to On (Automated) | Yes | Azure CLI or Powershell | - |
| 2.1.2 | Ensure That Microsoft Defender for App Services Is Set To On (Automated) | Yes | Azure CLI or Powershell | - |
| 2.1.3 | Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To On (Automated) | Yes | Azure CLI or Powershell | - |
| 2.1.4 | Ensure That Microsoft Defender for SQL Servers on Machines Is Set To On (Automated) | Yes | Azure CLI or Powershell | - |
| 2.1.5 | Ensure That Microsoft Defender for Open-Source Relational Databases Is Set To On (Automated) | Yes | Azure CLI or Powershell | - |
| 2.1.6 | Ensure That Microsoft Defender for Azure Cosmos DB Is Set To On (Automated) | Yes | Azure CLI or Powershell | - |
| 2.1.7 | Ensure That Microsoft Defender for Storage Is Set To On (Automated) | Yes | Azure CLI or Powershell | - |
| 2.1.8 | Ensure That Microsoft Defender for Containers Is Set To On (Automated) | Yes | Azure CLI or Powershell | - |
| 2.1.9 | Ensure That Microsoft Defender for Key Vault Is Set To On (Automated) | Yes | Azure CLI or Powershell | - |
| 2.1.10 | [LEGACY] Ensure That Microsoft Defender for DNS Is Set To On (Automated) | Yes | Azure CLI or Powershell | - |
| 2.1.11 | Ensure That Microsoft Defender for Resource Manager Is Set To On (Automated) | Yes | Azure CLI or Powershell | - |
| 2.1.12 | Ensure that Microsoft Defender Recommendation for Apply system updates status is Completed (Automated) | No | - | - |
| 2.1.13 | Ensure that Microsoft Cloud Security Benchmark policies are not set to Disabled (Manual) | No | - | - |
| 2.1.14 | Ensure that Auto provisioning of Log Analytics agent for Azure VMs is Set to On (Automated) | Yes | Azure CLI | - |
| 2.1.15 | Ensure that Auto provisioning of Vulnerability assessment for machines is Set to On (Manual) | No | - | - |
| 2.1.16 | Ensure that Auto provisioning of Microsoft Defender for Containers components is Set to On (Automated) | No | - | - |
| 2.1.17 | Ensure That All users with the following roles is set to Owner (Automated) | Yes | Azure CLI | - |
| 2.1.18 | Ensure Additional email addresses is Configured with a Security Contact Email (Automated) | Yes | Azure CLI | - |
| 2.1.19 | Ensure That Notify about alerts with the following severity is Set to High (Automated) | Yes | Azure CLI | - |
| 2.1.20 | Ensure that Microsoft Defender for Cloud Apps integration with Microsoft Defender for Cloud is Selected (Manual) | Yes | Azure CLI | - |
| 2.1.21 | Ensure that Microsoft Defender for Endpoint integration with Microsoft Defender for Cloud is selected (Manual) | Yes | Azure CLI | - |
| 2.1.22 | Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled (Manual) | No | - | - |
| 2.2 | Microsoft Defender for IoT | - | - | - |
| 2.2.1 | Ensure That Microsoft Defender for IoT Hub Is Set To On (Manual) | No | - | - |
| 3 | Storage Accounts | - | - | - |
| 3.1 | Ensure that Secure transfer required is set to Enabled (Automated) | Yes | Azure CLI | - |
| 3.2 | Ensure that Enable Infrastructure Encryption for Each Storage Account in Azure Storage is Set to enabled (Automated) | Yes | Azure CLI or Powershell | - |
| 3.3 | Ensure that Enable key rotation reminders is enabled for each Storage Account (Manual) | Yes | Azure CLI or Powershell | - |
| 3.4 | Ensure that Storage Account Access Keys are Periodically Regenerated (Manual) | Half | Azure CLI to audit | - |
| 3.5 | Ensure Storage Logging is Enabled for Queue Service for Read, Write, and Delete requests (Automated) | Yes | Azure CLI | - |
| 3.6 | Ensure that Shared Access Signature Tokens Expire Within an Hour (Manual) | No | - | - |
| 3.7 | Ensure that Public Network Access is Disabled for storage accounts (Automated) | Yes | Azure CLI or Powershell | - |
| 3.8 | Ensure Default Network Access Rule for Storage Accounts is Set to Deny (Automated) | Yes | Azure CLI | - |
| 3.9 | Ensure Allow Azure services on the trusted services list to access this storage account is Enabled for Storage Account Access (Automated) | Yes | Azure CLI or Powershell | - |
| 3.10 | Ensure Private Endpoints are used to access Storage Accounts (Automated) | Yes | Azure CLI | - |
| 3.11 | Ensure Soft Delete is Enabled for Azure Containers and Blob Storage (Automated) | Yes | Azure CLI | - |
| 3.12 | Ensure Storage for Critical Data are Encrypted with Customer Managed Keys (CMK) (Manual) | Half | Powershell to audit | - |
| 3.13 | Ensure Storage logging is Enabled for Blob Service for Read, Write, and Delete requests (Automated) | Yes | Azure CLI | - |
| 3.14 | Ensure Storage Logging is Enabled for Table Service for Read, Write, and Delete Requests (Automated) | Yes | Azure CLI | - |
| 3.15 | Ensure the Minimum TLS version for storage accounts is set to Version 1.2 (Automated) | Yes | Azure CLI | - |
| 3.16 | Ensure Cross Tenant Replication is not enabled (Automated) | Yes | Azure CLI | - |
| 3.17 | Ensure that Allow Blob Anonymous Access is set to Disabled (Automated) | Yes | Azure CLI audit and Powershell remediation | - |
| 4 | Database Services | - | - | - |
| 4.1 | SQL Server - Auditing | - | - | - |
| 4.1.1 | Ensure that Auditing is set to On (Automated) | Yes | Powershell | - |
| 4.1.2 | Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) (Automated) | Yes | Azure CLI or Powershell | - |
| 4.1.3 | Ensure SQL servers Transparent Data Encryption (TDE) protector is encrypted with Customer-managed key (Automated) | Yes | Azure CLI or Powershell | - |
| 4.1.4 | Ensure that Microsoft Entra authentication is Configured for SQL Servers (Automated) | Yes | Azure CLI | - |
| 4.1.5 | Ensure that Data encryption is set to On on a SQL Database (Automated) | Yes | Azure CLI or Powershell | - |
| 4.1.6 | Ensure that Auditing Retention is greater than 90 days (Automated) | Yes | Powershell | - |
| 4.3 | PostgreSQL Database Server | - | - | - |
| 4.3.1 | Ensure Enforce SSL connection is set to ENABLED for PostgreSQL Database Server (Automated) | Yes | Azure CLI or Powershell | - |
| 4.3.2 | Ensure Server Parameter log_checkpoints is set to ON for PostgreSQL Database Server (Automated) | Yes | Azure CLI or Powershell | - |
| 4.3.3 | Ensure server parameter log_connections is set to ON for PostgreSQL Database Server (Automated) | Yes | Azure CLI or Powershell | - |
| 4.3.4 | Ensure server parameter log_disconnections is set to ON for PostgreSQL Database Server (Automated) | Yes | Azure CLI or Powershell | - |
| 4.3.5 | Ensure server parameter connection_throttling is set to ON for PostgreSQL Database Server (Automated) | Yes | Azure CLI or Powershell | - |
| 4.3.6 | Ensure Server Parameter log_retention_days is greater than 3 days for PostgreSQL Database Server (Automated) | Yes | Azure CLI or Powershell | - |
| 4.3.7 | Ensure Allow access to Azure services for PostgreSQL Database Server is disabled (Automated) | Yes | Azure CLI | - |
| 4.3.8 | Ensure Infrastructure double encryption for PostgreSQL Database Server is Enabled (Automated) | Yes | Azure CLI | - |
| 4.4 | MySQL Database | - | - | - |
| 4.4.1 | Ensure Enforce SSL connection is set to Enabled for Standard MySQL Database Server (Automated) | Yes | Azure CLI | - |
| 4.4.2 | Ensure TLS Version is set to TLSV1.2 (or higher) for MySQL flexible Database Server (Automated) | Yes | Azure CLI | - |
| 4.4.3 | Ensure server parameter audit_log_enabled is set to ON for MySQL Database Server (Manual) | No | - | - |
| 4.4.4 | Ensure server parameter audit_log_events has CONNECTION set for MySQL Database Server (Manual) | No | - | - |
| 4.5 | Cosmos DB | - | - | - |
| 4.5.1 | Ensure That Firewalls & Networks Is Limited to Use Selected Networks Instead of All Networks (Automated) | Yes | Azure CLI | - |
| 4.5.2 | Ensure That Private Endpoints Are Used Where Possible (Automated) | No | - | - |
| 4.5.3 | Use Entra ID Client Authentication and Azure RBAC where possible (Manual) | Yes | Powershell | - |
| 5 | Logging and Monitoring | - | - | - |
| 5.1 | Configuring Diagnostic Settings | - | - | - |
| 5.1.1 | Ensure that a Diagnostic Setting exists for Subscription Activity Logs (Manual) | Yes | Azure CLI or Powershell | - |
| 5.1.2 | Ensure Diagnostic Setting captures appropriate categories (Automated) | Yes | Azure CLI or Powershell | - |
| 5.1.3 | Ensure the storage account containing the container with activity logs is encrypted with Customer Managed Key (CMK) (Automated) | Yes | Azure CLI or Powershell | - |
| 5.1.4 | Ensure that logging for Azure Key Vault is Enabled (Automated) | Yes | Azure CLI or Powershell | - |
| 5.1.5 | Ensure that Network Security Group Flow logs are captured and sent to Log Analytics (Manual) | No | - | - |
| 5.1.6 | Ensure that logging for Azure AppService HTTP logs is enabled (Manual) | No | - | - |
| 5.2 | Monitoring using Activity Log Alerts | - | - | - |
| 5.2.1 | Ensure that Activity Log Alert exists for Create Policy Assignment (Automated) | Yes | Azure CLI or Powershell | - |
| 5.2.2 | Ensure that Activity Log Alert exists for Delete Policy Assignment (Automated) | Yes | Azure CLI or Powershell | - |
| 5.2.3 | Ensure that Activity Log Alert exists for Create or Update Network Security Group (Automated) | Yes | Azure CLI or Powershell | - |
| 5.2.4 | Ensure that Activity Log Alert exists for Delete Network Security Group (Automated) | Yes | Azure CLI or Powershell | - |
| 5.2.5 | Ensure that Activity Log Alert exists for Create or Update Security Solution (Automated) | Yes | Azure CLI or Powershell | - |
| 5.2.6 | Ensure that Activity Log Alert exists for Delete Security Solution (Automated) | Yes | Azure CLI or Powershell | - |
| 5.2.7 | Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule (Automated) | Yes | Azure CLI or Powershell | - |
| 5.2.8 | Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule (Automated) | Yes | Azure CLI or Powershell | - |
| 5.2.9 | Ensure that Activity Log Alert exists for Create or Update Public IP Address rule (Automated) | Yes | Azure CLI or Powershell | - |
| 5.2.10 | Ensure that Activity Log Alert exists for Delete Public IP Address rule (Automated) | Yes | Azure CLI or Powershell | - |
| 5.3 | Configuring Application Insights | - | - | - |
| 5.3.1 | Ensure Application Insights are Configured (Automated) | Yes | Azure CLI or Powershell | - |
| 5.4 | Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it (Manual) | Yes | Azure CLI or Powershell | - |
| 5.5 | Ensure that SKU Basic/Consumption is not used on artifacts that need to be monitored (Particularly for Production Workloads) (Manual) | Yes | Azure CLI or Powershell | - |
| 6 | Networking | - | - | - |
| 6.1 | Ensure that RDP access from the Internet is evaluated and restricted (Automated) | Half | Azure CLI to audit | - |
| 6.2 | Ensure that SSH access from the Internet is evaluated and restricted (Automated) | Half | Azure CLI to audit | - |
| 6.3 | Ensure that UDP access from the Internet is evaluated and restricted (Automated) | Half | Azure CLI to audit | - |
| 6.4 | Ensure that HTTP(S) access from the Internet is evaluated and restricted (Automated) | Yes | Azure CLI | - |
| 6.5 | Ensure that Network Security Group Flow Log retention period is greater than 90 days (Automated) | Yes | Azure CLI | - |
| 6.6 | Ensure that Network Watcher is Enabled (Automated) | Yes | Azure CLI or Powershell | - |
| 6.7 | Ensure that Public IP addresses are Evaluated on a Periodic Basis (Manual) | Half | Azure CLI to audit | - |
| 7 | Virtual Machines | - | - | - |
| 7.1 | Ensure an Azure Bastion Host Exists (Automated) | Yes | Azure CLI or Powershell | - |
| 7.2 | Ensure Virtual Machines are utilizing Managed Disks (Automated) | Yes | Powershell | - |
| 7.3 | Ensure that OS and Data disks are encrypted with Customer Managed Key (CMK) (Automated) | Yes | Powershell | - |
| 7.4 | Ensure that Unattached disks are encrypted with Customer Managed Key (CMK) (Automated) | Yes | Azure CLI | - |
| 7.5 | Ensure that Only Approved Extensions Are Installed (Manual) | Yes | Azure CLI or Powershell | - |
| 7.6 | Ensure that Endpoint Protection for all Virtual Machines is installed (Manual) | Yes | Azure CLI | - |
| 7.7 | [Legacy] Ensure that VHDs are Encrypted (Manual) | Yes | Azure CLI or Powershell | - |
| 7.8 | Ensure only MFA enabled identities can access privileged Virtual Machine (Automated) | No | - | - |
| 7.9 | Ensure Trusted Launch is enabled on Virtual Machines (Automated) | No | - | - |
| 8 | Key Vault | - | - | - |
| 8.1 | Ensure that the Expiration Date is set for all Keys in RBAC Key Vaults (Automated) | Yes | Azure CLI or Powershell | - |
| 8.2 | Ensure that the Expiration Date is set for all Keys in Non-RBAC Key Vaults (Automated) | Yes | Azure CLI or Powershell | - |
| 8.3 | Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults (Automated) | Yes | Azure CLI or Powershell | - |
| 8.4 | Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults (Automated) | Yes | Azure CLI or Powershell | - |
| 8.5 | Ensure the Key Vault is Recoverable (Automated) | Yes | Azure CLI or Powershell | - |
| 8.6 | Enable Role Based Access Control for Azure Key Vault (Manual) | Yes | Azure CLI or Powershell | - |
| 8.7 | Ensure that Private Endpoints are Used for Azure Key Vault (Manual) | Yes | Azure CLI | - |
| 8.8 | Ensure Automatic Key Rotation is Enabled Within Azure Key Vault for the Supported Services (Manual) | Yes | Azure CLI or Powershell | - |
| 9 | AppService | - | - | - |
| 9.1 | Ensure App Service Authentication is set up for apps in Azure App Service (Automated) | Yes | Azure CLI | - |
| 9.2 | Ensure Web App Redirects All HTTP traffic to HTTPS in Azure App Service (Automated) | Yes | Azure CLI or Powershell | - |
| 9.3 | Ensure Web App is using the latest version of TLS encryption (Automated) | Yes | Azure CLI or Powershell | - |
| 9.4 | Ensure that Register with Entra ID is enabled on App Service (Automated) | Yes | Azure CLI or Powershell | - |
| 9.5 | Ensure That PHP version is the Latest, If Used to Run the Web App (Manual) | Yes | Azure CLI or Powershell | - |
| 9.6 | Ensure that Python version is the Latest Stable Version, if Used to Run the Web App (Manual) | Yes | Azure CLI | - |
| 9.7 | Ensure that Java version is the latest, if used to run the Web App (Manual) | Yes | Azure CLI | - |
| 9.8 | Ensure that HTTP Version is the Latest, if Used to Run the Web App (Automated) | Yes | Azure CLI or Powershell | - |
| 9.9 | Ensure FTP deployments are Disabled (Automated) | Yes | Azure CLI or Powershell | - |
| 9.10 | Ensure Azure Key Vaults are Used to Store Secrets (Manual) | Yes | Azure CLI or Powershell | - |
| 10 | Miscellaneous | - | - | - |
| 10.1 | Ensure that Resource Locks are set for Mission-Critical Azure Resources (Manual) | Yes | Azure CLI or Powershell | - |
| - | - | Number of Automatable | 101 | - |
| - | - | Number of Half-Automatable | 11 | - |
| - | - | Number of Non-automatable | 36 | - |
| - | - | Total Number of Controls | 148 | - |


For any controls marked as 'Manual', please refer to the following following at [SAF-CLI](https://saf-cli.mitre.org/) on how to apply manual attestations to the output of an automated assessment. The following [link](https://vmware.github.io/dod-compliance-and-automation/docs/automation-tools/safcli/) that references the SAF-CLI is also useful.

[top](#table-of-contents)

## Authors
[Center for Internet Security (CIS)](https://www.cisecurity.org/)
 
[MITRE Security Automation Framework Team](https://saf.mitre.org)
 
## NOTICE
 
© 2018-2025 The MITRE Corporation.
 
Approved for Public Release; Distribution Unlimited. Case Number 18-3678.
 
## NOTICE
 
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.
 
## NOTICE  
 
This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  
 
No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.
 
For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.
 
## NOTICE
[CIS Benchmarks are published by Center for Internet Security](https://www.cisecurity.org/cis-benchmarks)