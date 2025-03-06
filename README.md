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

## Table of Contents

- [CIS Benchmark Information](#benchmark-information)

- [Requirements](#requirements)
  - [Required Software](#required-software)
  - [Azure Environment Setup](#azure-account-configuration)
- [Getting Started](#getting-started)
  - [Intended Usage](#intended-usage)
  - [Tailoring to Your Environment](#tailoring-to-your-environment)
  - [Testing the Profile Controls](#testing-the-profile-controls)
- [Setup the Profile](#setup-the-profile)
- [Running the Profile](#running-the-profile)
  - [Different Run Options](#different-run-options)
- [Using Heimdall for Viewing Test Results](#using-heimdall-for-viewing-test-results)
- [Check Overview](#check-overview)

## Benchmark Information

The Center for Internet Security, Inc. (CIS®) create and maintains a set of Critical Security Controls (CIS Controls) for applications, computer systems and networks.

The original benchmark document that serves as the basis for this automated testing profile can be found at the [CIS Workbench](https://workbench.cisecurity.org) website.

## Requirements

### Required Software

- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
- [CINC-auditor](https://cinc.sh/start/auditor/) or [InSpec](https://docs.chef.io/inspec/install/)
- [PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-7.4)
  - [Microsoft Azure Powershell Module](https://learn.microsoft.com/en-us/powershell/azure/install-azure-powershell?view=azps-13.2.0)
  - [Microsoft Graph Powershell Module](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0)
- [Ruby](https://www.ruby-lang.org/en/documentation/installation/)

### Azure Account Configuration

To successfully authenticate your application with Azure, you need to obtain the following credentials from your app registration:

- subscription_id
- client_id
- tenant_id
- client_secret

#### 1. Retrieve App Registration Credentials

1. **Register Your App in Azure Portal**

    Log in to **Azure Portal** → **App registrations** → **New registration**. Complete the required fields and register your application.

2. **Retrieve Application IDs**

    - **Client ID:** Located on the app’s **Overview** page.
    - **Tenant ID:** Also available on the **Overview** page.

3. **Create a Client Secret**

    In your application’s menu, select **Manage** → **Certificates & secrets** → **New client secret**. Provide a description and set an expiration period. Store the generated secret value as it will not be visible later.

4. **Get Subscription ID**

    Go to **Subscriptions** in the portal, select your subscription, and copy the **Subscription ID**.

    Reference: [Application Registration Steps](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=certificate)


1. **Connect to Azure Modules**

    Open PowerShell and run the following commands to authenticate using your service principal:

    ```sh
    $credential = New-Object System.Management.Automation.PSCredential("<INSERT_CLIENT_ID>", (ConvertTo-SecureString "<INSERT_CLIENT_SECRET>" -AsPlainText -Force))
    Connect-AzAccount -ServicePrincipal -TenantId "<INSERT_TENANT_ID>" -Credential $credential
    ```

    If you receive output confirming the connection, you are successfully authenticated.

2. **Connect to Azure CLI**

    In PowerShell, execute this command to log in via the Azure CLI:

    ```sh
    az login --service-principal --username "<INSERT_CLIENT_ID>" --password "<INSERT_CLIENT_SECRET>" --tenant "<INSERT TENANT_ID>"
    ```

    A successful output indicates that you are connected.

#### 3. Ensure Proper Azure Permissions

Ensure that both your runner account and service principal (app registration) have Owner and Reader roles. Additionally, make sure that you have the permissions below for each resource:

**Required Permissions by Resource:**

- **Key Vault**
  - **Role:** Key Vault Administrator
  - **Verification:** Navigate to your Key Vault in Azure Portal, then go to **Access Control (IAM)** → **Role Assignments**. Confirm that you have the ***Key Vault Administrator*** role.

- **Storage Accounts**
  - **Role:** App Compliance Automation Administrator
  - **Verification:** Navigate to your Storage Account in Azure Portal, then go to **Access Control (IAM)** → **Role Assignments**. Confirm that you have the ***App Compliance Automation Administrator*** role.

  The following permissions are needed for the following resources.
  
  Key Vault
    - Key Vault Administrator
  Storage Accounts
    - App Compliance Automation Administrator

## Getting Started

### InSpec (CINC Auditor) setup

For maximum flexibility/accessibility, CINC Auditor (`cinc-auditor`) is the executable program that should be used to run this testing profile.

CINC Auditor is the open-source packaged binary version of Chef InSpec,
compiled by the CINC (CINC Is Not Chef) project in coordination with Chef using Chef's always-open-source InSpec source code. CINC Auditor and InSpec are built from the same source code and function identically, but CINC Auditor requires no license to use (which means it also does not come with any expectation of support from Chef).

For more information see [CINC Home](https://cinc.sh/)

It is intended and recommended that CINC Auditor and this profile executed from a **"runner"** host
(such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop)
against the target. This can be any Unix/Linux/MacOS or Windows runner host, with access to the Internet.

> [TIP] > **For the best security of the runner, always install on the runner the latest version of CINC Auditor and any other supporting language components.**

To install CINC Auditor on a UNIX/Linux/MacOS platform use the following command:

```bash
curl -L https://omnitruck.cinc.sh/install.sh | sudo bash -s -- -P cinc-auditor
```

To install CINC Auditor on a Windows platform (PowerShell) use the following command:

```powershell
. { iwr -useb https://omnitruck.cinc.sh/install.ps1 } | iex; install -project cinc-auditor
```

To confirm successful install of CINC Auditor:

```bash
cinc-auditor -v
```

Latest versions and other installation options are available at [CINC Auditor](https://cinc.sh/start/auditor/)'s website.

### Intended Usage

1. The latest `released` version of the profile is intended for use in A&A testing, as well as
   providing formal results to Authorizing Officials and Identity and Access Management (IAM)s.
   Please use the `released` versions of the profile in these types of workflows.

2. The `main` branch is a development branch that will become the next release of the profile.
   The `main` branch is intended for use in *developing and testing* merge requests for the next
   release of the profile, and *is not intended* be used for formal and ongoing testing on systems.

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

#### Example of tailoring Inputs *While Still Complying* with the security guidance document for the profile

> [NOTE]
> Inputs are variables that are referenced by control(s) in the profile that implement them.
> They are declared (defined) and given a default value in the `inspec.yml` file.

#### Using Customized Inputs

Customized inputs may be used at the CLI by providing an input file or a flag at execution time.

1. Using the `--input` flag

   Example: `[inspec or cinc-auditor] exec <my-profile.tar.gz> --input disable_slow_controls=true`

2. Using the `--input-file` flag.

   Example: `[inspec or cinc-auditor] exec <my-profile.tar.gz> --input-file=<my_inputs_file.yml>`

> [TIP]
> For additional information about `input` file examples reference the [MITRE SAF Training](https://mitre.github.io/saf-training/courses/beginner/06.html#input-file-example)

Chef InSpec Resources:

- [InSpec Profile Documentation](https://docs.chef.io/inspec/profiles/)
- [InSpec Inputs](https://docs.chef.io/inspec/profiles/inputs/)
- [inspec.yml](https://docs.chef.io/inspec/profiles/inspec_yml/)

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

## Setup the Profile

1. **Clone the Repository**

    Start by cloning the `azure-foundations-cis-baseline` repository from GitHub to your local machine:

    ```sh
    git clone https://github.com/mitre/azure-foundations-cis-baseline.git
    cd azure-foundations-cis-baseline
    ```

2. **Clone the Repository**

    Once the repository is cloned, install the required Ruby dependencies by running:

    ```sh
    bundle install
    ```

3. **Create and Update `inputs.yml` for Inspec**

   Execute the following command to create the `inputs.yml` file by copying `inputs_template.yml` and renaming it to `inputs.yml`.
   Update this file with your values.

   ```sh
   cp inputs_template.yml inputs.yml
   ```

### Example `inputs.yml`

```yaml
# Azure Connection Settings
subscription_id: "00000000-0000-0000-0000-000000000000"
client_id: "00000000-0000-0000-0000-000000000000"
tenant_id: "00000000-0000-0000-0000-000000000000"
client_secret: "0000000000000000000000000000000000000000"

# Resource Configuration
resource_groups_and_storage_accounts:
  - "group1.account1"
key_vault_full_key_uri:
  - "https://test.vault.azure.net/keys/vault-key-name/current-version"

# Control 7.7
relevant_public_ip_addresses:
  - "1"
  - "2"

# Control 8.7
resource_group_and_disk_name:
  - "group1.disk1"
unauthorized_extension_names:
  - "test"
unauthorized_extension_types:
  - "google"
unauthorized_provision_states:
  - "test"

# Controls 3.3.1, 3.3.2, 3.3.3, 3.3.4
# Provide expiration dates in the order the keys appear in the GUI
# For example, list Vault 1’s Key 1 first, followed by subsequent keys and vaults in sequence.
# Use "null" to omit a date. Format for dates: "M/d/yyyy h:mm:ss tt"
rbac_keys_appropriate_expiry_date:
  - "2/28/2027 8:57:19 PM"
  - "null"
non_rbac_keys_appropriate_expiry_date:
  - "2/28/2027 8:57:19 PM"
  - "null"
rbac_secrets_appropriate_expiry_date:
  - "2/28/2027 8:57:19 PM"
  - "null"
non_rbac_secrets_appropriate_expiry_date:
  - "2/28/2027 8:57:19 PM"
  - "null"
```

## Running the Profile

### Execute All Controls in the Profile

```sh
bundle exec [inspec or cinc-auditor] exec . --enhanced-outcomes  --input-file=inputs.yml
```

#### Execute All the Controls in the Profile and Save Results as Json

```sh
bundle exec [inspec or cinc-auditor] exec . --enhanced-outcomes  --reporter json:results.json --input-file=inputs.yml
```

### Execute a Single Control and Save Results as Json

Replace [control-number] with the actual control number (e.g., use 5.1.6 to target azure-foundations-cis-5.1.6)

```sh
bundle exec [inspec or cinc-auditor] exec . --enhanced-outcomes  --reporter json:results.json --input-file=inputs.yml --controls=azure-foundations-cis-[control-number]
```

## Different Run Options

[Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Using Heimdall for Viewing Test Results

The JSON results output file can be loaded into **[Heimdall-Lite](https://heimdall-lite.mitre.org/)**
or **[Heimdall-Server](https://github.com/mitre/heimdall2)** for a user-interactive, graphical view of the profile scan results.

Heimdall-Lite is a `browser only` viewer that allows you to easily view your results directly and locally rendered in your browser.
Heimdall-Server is configured with a `data-services backend` allowing for data persistency to a database (PostgreSQL).
For more detail on feature capabilities see [Heimdall Features](https://github.com/mitre/heimdall2?tab=readme-ov-file#features)

Heimdall can ***export your results into a DISA Checklist (CKL) file*** for easily uploading into eMass using the `Heimdall Export` function.

Depending on your environment restrictions, the [SAF CLI](https://saf-cli.mitre.org) can be used to run a local docker instance
of Heimdall-Lite via the `saf view:heimdall` command.

Additionally both Heimdall applications can be deployed via docker, kubernetes, or the installation packages.

## Check Overview

### Azure Services

This profile requires the following Azure services to be properly configured in order to run effectively.

- App Services
- Azure CosmosDB
- Azure Database for MySQL flexible servers
- Azure Database for PostgreSQL flexible servers
- Azure SQL
- Bastions
- Microsoft Defender for Cloud
- Microsoft Entra ID
- Key Vaults
- Log Analytics workspaces
- Network Watcher
- Storage Accounts

### Control and Automation Status

Not all controls in the CIS Benchmark are capable of automated assessment. The table below marks which controls are automated and which ones are manual.

| Number  | Description                                                                                                                                                    | Automatable                | Implementation           |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------ |
| 2       | Identity                                                                                                                                                       | -                          | -                        |
| 2.1     | Security Defaults (Per-User MFA)                                                                                                                               | -                          | -                        |
| 2.1.1   | Ensure Security Defaults is enabled on Microsoft Entra ID (Manual)                                                                                             | No                         | -                        |
| 2.1.2   | Ensure that Multi-Factor Auth Status is Enabled for all Privileged Users (Manual)                                                                              | Yes                        | REST API to audit        |
| 2.1.3   | Ensure that Multi-Factor Auth Status is Enabled for all Non-Privileged Users (Manual)                                                                          | Yes                        | REST API to audit        |
| 2.1.4   | Ensure that Allow users to remember multi-factor authentication on devices they trust is Disabled (Manual)                                                     | No                         | -                        |
| -       | -                                                                                                                                                              | -                          | -                        |
| 2.2     | Conditional Access                                                                                                                                             | -                          | -                        |
| 2.2.1   | Ensure Trusted Locations Are Defined (Manual)                                                                                                                  | Yes                        | Powershell               |
| 2.2.2   | Ensure that an exclusionary Geographic Access Policy is considered (Manual)                                                                                    | Yes                        | Powershell               |
| 2.2.3   | Ensure that an exclusionary Device code flow policy is considered (Manual)                                                                                     | No                         | -                        |
| 2.2.4   | Ensure that A Multi-factor Authentication Policy Exists for Administrative Groups (Manual)                                                                     | No                         | -                        |
| 2.2.5   | Ensure that A Multi-factor Authentication Policy Exists for All Users (Manual)                                                                                 | No                         | -                        |
| 2.2.6   | Ensure Multi-factor Authentication is Required for Risky Sign-ins (Manual)                                                                                     | No                         | -                        |
| 2.2.7   | Ensure Multi-factor Authentication is Required for Windows Azure Service Management API (Manual)                                                               | No                         | -                        |
| 2.2.8   | Ensure Multi-factor Authentication is Required to access Microsoft Admin Portals (Manual)                                                                      | No                         | -                        |
| -       | -                                                                                                                                                              | -                          | -                        |
| 2.3     | Ensure that Restrict non-admin users from creating tenants is set to Yes (Automated)                                                                           | Yes                        | Powershell               |
| 2.4     | Ensure Guest Users Are Reviewed on a Regular Basis (Manual)                                                                                                    | Yes                        | Azure CLI or Powershell  |
| 2.5     | Ensure That Number of methods required to reset is set to 2 (Manual)                                                                                           | No                         | -                        |
| 2.6     | Ensure that account Lockout Threshold is less than or equal to 10 (Manual)                                                                                     | No                         | -                        |
| 2.7     | Ensure that account Lockout duration in seconds is greater than or equal to 60 (Manual)                                                                        | No                         | -                        |
| 2.8     | Ensure that a Custom Bad Password List is set to Enforce for your Organization (Manual)                                                                        | No                         | -                        |
| 2.9     | Ensure that Number of days before users are asked to re-confirm their authentication information is not set to 0 (Manual)                                      | No                         | -                        |
| 2.10    | Ensure that Notify users on password resets? is set to Yes (Manual)                                                                                            | No                         | -                        |
| 2.11    | Ensure That Notify all admins when other admins reset their password? is set to Yes (Manual)                                                                   | No                         | -                        |
| 2.12    | Ensure User consent for applications is set to Do not allow user consent (Manual)                                                                              | Yes                        | Powershell to audit      |
| 2.13    | Ensure User consent for applications Is Set To Allow for Verified Publishers (Manual)                                                                          | Yes                        | Powershell to audit      |
| 2.14    | Ensure That Users Can Register Applications Is Set to No (Automated)                                                                                           | Yes                        | Powershell               |
| 2.15    | Ensure That Guest users access restrictions is set to Guest user access is restricted to properties and memberships of their own directory objects (Automated) | Yes                        | Powershell               |
| 2.16    | Ensure that Guest invite restrictions is set to Only users assigned to specific admin roles can invite guest users (Automated)                                 | Yes                        | Powershell               |
| 2.17    | Ensure That Restrict access to Microsoft Entra admin center is Set to Yes (Manual)                                                                             | No                         | -                        |
| 2.18    | Ensure that Restrict user ability to access groups features in the Access Pane is Set to Yes (Manual)                                                          | No                         | -                        |
| 2.19    | Ensure that Users can create security groups in Azure portals, API or PowerShell is set to No (Manual)                                                         | No                         | -                        |
| 2.20    | Ensure that Owners can manage group membership requests in My Groups is set to No (Manual)                                                                     | No                         | -                        |
| 2.21    | Ensure that Users can create Microsoft 365 groups in Azure portals, API or PowerShell is set to No (Manual)                                                    | No                         | -                        |
| 2.22    | Ensure that Require Multifactor Authentication to register or join devices with Microsoft Entra is set to Yes (Manual)                                         | No                         | -                        |
| 2.23    | Ensure That No Custom Subscription Administrator Roles Exist (Automated)                                                                                       | Yes                        | Azure CLI or Powershell  |
| 2.24    | Ensure a Custom Role is Assigned Permissions for Administering Resource Locks (Manual)                                                                         | No                        | Powershell to remediate  |
| 2.25    | Ensure That Subscription leaving Microsoft Entra tenant and Subscription entering Microsoft Entra tenant Is Set To Permit no one (Manual)                      | No                         | -                        |
| 2.26    | Ensure fewer than 5 users have global administrator assignment (Manual)                                                                                        | No                         | -                        |
| -       | -                                                                                                                                                              | -                          | -                        |
| 3       | Security                                                                                                                                                       | -                          | -                        |
| 3.1     | Microsoft Defender for Cloud                                                                                                                                   | -                          | -                        |
| 3.1.1   | Microsoft Cloud Security Posture Management (CSPM)                                                                                                             | -                          | -                        |
| 3.1.1.1 | Ensure that Auto provisioning of Log Analytics agent for Azure VMs is Set to On (Automated)                                                                    | Yes                        | Azure CLI or Powershell  |
| 3.1.1.2 | Ensure that Microsoft Defender for Cloud Apps integration with Microsoft Defender for Cloud is Selected (Automated)                                            | Yes                        | Azure CLI or Powershell  |
| 3.1.2   | Defender Plan: APIs                                                                                                                                            | -                          | -                        |
| 3.1.3   | Defender Plan: Servers                                                                                                                                         | -                          | -                        |
| 3.1.3.1 | Ensure That Microsoft Defender for Servers Is Set to On (Automated)                                                                                            | Yes                        | Azure CLI or Powershell  |
| 3.1.3.2 | Ensure that Vulnerability assessment for machines component status is set to On (Manual)                                                                       | No                         | -                        |
| 3.1.3.3 | Ensure that Endpoint protection component status is set to On (Manual)                                                                                         | Yes                        | Azure CLI or Powershell  |
| 3.1.3.4 | Ensure that Agentless scanning for machines component status is set to On (Manual)                                                                             | No                         | -                        |
| 3.1.3.5 | Ensure that File Integrity Monitoring component status is set to On (Manual)                                                                                   | No                         | -                        |
| 3.1.4   | Defender Plan: Containers                                                                                                                                      | -                          | -                        |
| 3.1.4.1 | Ensure That Microsoft Defender for Containers Is Set To On (Automated)                                                                                         | Yes                        | Azure CLI or Powershell  |
| 3.1.4.2 | Ensure that Agentless discovery for Kubernetes component status is On (Automated)                                                                              | No                         | -                        |
| 3.1.4.3 | Ensure that Agentless container vulnerability assessment component status is On (Automated)                                                                    | No                         | -                        |
| 3.1.5   | Defender Plan: Storage                                                                                                                                         | -                          | -                        |
| 3.1.5.1 | Ensure That Microsoft Defender for Storage Is Set To On (Automated)                                                                                            | Yes                        | Azure CLI or Powershell  |
| 3.1.6   | Defender Plan: App Service                                                                                                                                     | -                          | -                        |
| 3.1.6.1 | Ensure That Microsoft Defender for App Services Is Set To On (Automated)                                                                                       | Yes                        | Azure CLI or Powershell  |
| 3.1.7   | Defender Plan: Databases                                                                                                                                       | -                          | -                        |
| 3.1.7.1 | Ensure That Microsoft Defender for Azure Cosmos DB Is Set To On (Automated)                                                                                    | Yes                        | Azure CLI or Powershell  |
| 3.1.7.2 | Ensure That Microsoft Defender for Open-Source Relational Databases Is Set To On (Automated)                                                                   | Yes                        | Azure CLI or Powershell  |
| 3.1.7.3 | Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To On (Automated)                                                             | Yes                        | Azure CLI or Powershell  |
| 3.1.7.4 | Ensure That Microsoft Defender for SQL Servers on Machines Is Set To On (Automated)                                                                            | Yes                        | Azure CLI or Powershell  |
| 3.1.8   | Defender Plan: Key Vault                                                                                                                                       | -                          | -                        |
| 3.1.8.1 | Ensure That Microsoft Defender for Key Vault Is Set To On (Automated)                                                                                          | Yes                        | Azure CLI or Powershell  |
| 3.1.9   | Defender Plan: Resource Manager                                                                                                                                | -                          | -                        |
| 3.1.9.1 | Ensure That Microsoft Defender for Resource Manager Is Set To On (Automated)                                                                                   | Yes                        | Azure CLI or Powershell  |
| 3.1.10  | Ensure that Microsoft Defender Recommendation for Apply system updates status is Completed (Automated)                                                         | No                         | -                        |
| 3.1.11  | Ensure that Microsoft Cloud Security Benchmark policies are not set to Disabled (Manual)                                                                       | No                         | -                        |
| 3.1.12  | Ensure That All users with the following roles is set to Owner (Automated)                                                                                     | Yes                        | Azure CLI                |
| 3.1.13  | Ensure Additional email addresses is Configured with a Security Contact Email (Automated)                                                                      | Yes                        | Azure CLI                |
| 3.1.14  | Ensure That Notify about alerts with the following severity is Set to High (Automated)                                                                         | Yes                        | Azure CLI                |
| 3.1.15  | Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled (Manual)                                                                   | No                         | -                        |
| 3.1.16  | [LEGACY] Ensure That Microsoft Defender for DNS Is Set To On (Automated)                                                                                       | Yes                        | Azure CLI or Powershell  |
| -       | -                                                                                                                                                              | -                          | -                        |
| 3.2     | Microsoft Defender for IoT                                                                                                                                     | -                          | -                        |
| 3.2.1   | Ensure That Microsoft Defender for IoT Hub Is Set To On (Manual)                                                                                               | No                         | -                        |
| -       | -                                                                                                                                                              | -                          | -                        |
| 3.3     | Key Vault                                                                                                                                                      | -                          | -                        |
| 3.3.1   | Ensure that the Expiration Date is set for all Keys in RBAC Key Vaults (Automated)                                                                             | Yes                        | Azure CLI or Powershell  |
| 3.3.2   | Ensure that the Expiration Date is set for all Keys in Non-RBAC Key Vaults (Automated)                                                                         | Yes                        | Azure CLI or Powershell  |
| 3.3.3   | Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults (Automated)                                                                          | Yes                        | Azure CLI or Powershell  |
| 3.3.4   | Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults (Automated)                                                                      | Yes                        | Azure CLI or Powershell  |
| 3.3.5   | Ensure the Key Vault is Recoverable (Automated)                                                                                                                | Yes                        | Azure CLI or Powershell  |
| 3.3.6   | Enable Role Based Access Control for Azure Key Vault (Automated)                                                                                               | Yes                        | Azure CLI or Powershell  |
| 3.3.7   | Ensure that Private Endpoints are Used for Azure Key Vault (Automated)                                                                                         | Yes                        | Azure CLI or Powershell  |
| 3.3.8   | Ensure Automatic Key Rotation is Enabled Within Azure Key Vault for the Supported Services (Automated)                                                         | Yes                        | Azure CLI or Powershell  |
| -       | -                                                                                                                                                              | -                          | -                        |
| 4       | Storage Accounts                                                                                                                                               | -                          | -                        |
| 4.1     | Ensure that Secure transfer required is set to Enabled (Automated)                                                                                             | Yes                        | Azure CLI                |
| 4.2     | Ensure that Enable Infrastructure Encryption for Each Storage Account in Azure Storage is Set to Enabled (Automated)                                           | Yes                        | Azure CLI or Powershell  |
| 4.3     | Ensure that Enable key rotation reminders is enabled for each Storage Account (Manual)                                                                         | Yes                        | Azure CLI and Powershell |
| 4.4     | Ensure that Storage Account Access Keys are Periodically Regenerated (Manual)                                                                                  | Yes                        | Azure CLI                |
| 4.5     | Ensure that Shared Access Signature Tokens Expire Within an Hour (Manual)                                                                                      | No                         | -                        |
| 4.6     | Ensure that Public Network Access is Disabled for storage accounts (Automated)                                                                                 | Yes                        | Azure CLI and Powershell |
| 4.7     | Ensure Default Network Access Rule for Storage Accounts is Set to Deny (Automated)                                                                             | Yes                        | Azure CLI                |
| 4.8     | Ensure Allow Azure services on the trusted services list to access this storage account is Enabled for Storage Account Access (Automated)                      | Yes                        | Azure CLI and Powershell |
| 4.9     | Ensure Private Endpoints are used to access Storage Accounts (Automated)                                                                                       | Yes                        | Azure CLI or Powershell  |
| 4.10    | Ensure Soft Delete is Enabled for Azure Containers and Blob Storage (Automated)                                                                                | Yes                        | Azure CLI                |
| 4.11    | Ensure Storage for Critical Data are Encrypted with Customer Managed Keys (CMK) (Manual)                                                                       | Yes                        | Powershell               |
| 4.12    | Ensure Storage Logging is Enabled for Queue Service for Read, Write, and Delete requests (Automated)                                                           | Yes                        | Azure CLI                |
| 4.13    | Ensure Storage logging is Enabled for Blob Service for Read, Write, and Delete requests (Automated)                                                            | Yes                        | Azure CLI                |
| 4.14    | Ensure Storage Logging is Enabled for Table Service for Read, Write, and Delete Requests (Automated)                                                           | Yes                        | Azure CLI                |
| 4.15    | Ensure the Minimum TLS version for storage accounts is set to Version 1.2 (Automated)                                                                          | Yes                        | Azure CLI or Powershell  |
| 4.16    | Ensure Cross Tenant Replication is not enabled (Automated)                                                                                                     | Yes                        | Azure CLI                |
| 4.17    | Ensure that Allow Blob Anonymous Access is set to Disabled (Automated)                                                                                         | Yes                        | Azure CLI and Powershell |
| -       | -                                                                                                                                                              | -                          | -                        |
| 5       | Database Services                                                                                                                                              | -                          | -                        |
| 5.1     | Azure SQL Database                                                                                                                                             | -                          | -                        |
| 5.1.1   | Ensure that 'Auditing' is set to 'On'                                                                                                                          | Yes                        | Powershell               |
| 5.1.2   | Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)                                                                                            | Yes                        | Azure CLI or Powershell  |
| 5.1.3   | Ensure SQL server's Transparent Data Encryption (TDE) protector is encrypted with Customer-managed key                                                         | Yes                        | Azure CLI or Powershell  |
| 5.1.4   | Ensure that Microsoft Entra authentication is Configured for SQL Servers                                                                                       | Yes                        | Azure CLI or Powershell  |
| 5.1.5   | Ensure that 'Data encryption' is set to 'On' on a SQL Database                                                                                                 | Yes                        | Azure CLI or Powershell  |
| 5.1.6   | Ensure that 'Auditing' Retention is 'greater than 90 days'                                                                                                     | Yes                        | Powershell               |
| 5.1.7   | Ensure Public Network Access is Disabled                                                                                                                       | No                         | -                        |
| -       | -                                                                                                                                                              | -                          | -                        |
| 5.2     | Azure Database for PostgreSQL                                                                                                                                  | -                          | -                        |
| 5.2.1   | Ensure server parameter 'require_secure_transport' is set to 'ON' for PostgreSQL flexible server                                                               | Yes                        | Azure CLI or Powershell  |
| 5.2.2   | Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL flexible server                                                                        | Yes                        | Azure CLI or Powershell  |
| 5.2.3   | Ensure server parameter 'connection_throttle.enable' is set to 'ON' for PostgreSQL flexible server                                                             | Yes                        | Azure CLI or Powershell  |
| 5.2.4   | Ensure server parameter 'logfiles.retention_days' is greater than 3 days for PostgreSQL flexible server                                                        | Yes                        | Azure CLI or Powershell  |
| 5.2.5   | Ensure 'Allow public access from any Azure service within Azure to this server' for PostgreSQL flexible server is disabled                                     | Yes                        | Azure CLI or Powershell  |
| 5.2.6   | [LEGACY] Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL single server                                                                 | Yes                        | Azure CLI or Powershell  |
| 5.2.7   | [LEGACY] Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL single server                                                              | Yes                        | Azure CLI or Powershell  |
| 5.2.8   | [LEGACY] Ensure 'Infrastructure double encryption' for PostgreSQL single server is 'Enabled'                                                                   | Yes                        | Azure CLI                |
| -       | -                                                                                                                                                              | -                          | -                        |
| 5.3     | Azure Database for MySQL                                                                                                                                       | -                          | -                        |
| 5.3.1   | Ensure server parameter 'require_secure_transport' is set to 'ON' for MySQL flexible server                                                                    | Yes                        | Azure CLI or Powershell  |
| 5.3.2   | Ensure server parameter 'tls_version' is set to 'TLSv1.2' (or higher) for MySQL flexible server                                                                | Yes                        | Azure CLI or Powershell  |
| 5.3.3   | Ensure server parameter 'audit_log_enabled' is set to 'ON' for MySQL flexible server                                                                           | Yes                        | Azure CLI or Powershell  |
| 5.3.4   | Ensure server parameter 'audit_log_events' has 'CONNECTION' set for MySQL flexible server                                                                      | Yes                        | Azure CLI or Powershell  |
| -       | -                                                                                                                                                              | -                          | -                        |
| 5.4     | Azure Cosmos DB                                                                                                                                                | -                          | -                        |
| 5.4.1   | Ensure That 'Firewalls & Networks' Is Limited to Use Selected Networks Instead of All Networks                                                                 | Yes                        | Azure CLI                |
| 5.4.2   | Ensure That Private Endpoints Are Used Where Possible                                                                                                          | No                         | -                        |
| 5.4.3   | Use Entra ID Client Authentication and Azure RBAC where possible                                                                                               | Yes                        | Powershell               |
| -       | -                                                                                                                                                              | -                          | -                        |
| 6       | Logging and Monitoring                                                                                                                                         | -                          | -                        |
| 6.1.1   | Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs                                                                                       | Yes                        | Azure CLI or Powershell  |
| 6.1.2   | Ensure Diagnostic Setting captures appropriate categories                                                                                                      | Yes                        | Azure CLI or Powershell  |
| 6.1.3   | Ensure the storage account containing the container with activity logs is encrypted with Customer Managed Key (CMK)                                            | Yes                        | Azure CLI or Powershell  |
| 6.1.4   | Ensure that logging for Azure Key Vault is 'Enabled'                                                                                                           | Yes                        | Azure CLI or Powershell  |
| 6.1.5   | Ensure that Network Security Group Flow logs are captured and sent to Log Analytics                                                                            | No                         | -                        |
| 6.1.6   | Ensure that logging for Azure AppService 'HTTP logs' is enabled                                                                                                | No                         | -                        |
| -       | -                                                                                                                                                              | -                          | -                        |
| 6.2     | Monitoring using Activity Log Alerts                                                                                                                           | -                          | -                        |
| 6.2.1   | Ensure that Activity Log Alert exists for Create Policy Assignment                                                                                             | Yes                        | Azure CLI or Powershell  |
| 6.2.2   | Ensure that Activity Log Alert exists for Delete Policy Assignment                                                                                             | Yes                        | Azure CLI or Powershell  |
| 6.2.3   | Ensure that Activity Log Alert exists for Create or Update Network Security Group                                                                              | Yes                        | Azure CLI or Powershell  |
| 6.2.4   | Ensure that Activity Log Alert exists for Delete Network Security Group                                                                                        | Yes                        | Azure CLI or Powershell  |
| 6.2.5   | Ensure that Activity Log Alert exists for Create or Update Security Solution                                                                                   | Yes                        | Azure CLI or Powershell  |
| 6.2.6   | Ensure that Activity Log Alert exists for Delete Security Solution                                                                                             | Yes                        | Azure CLI or Powershell  |
| 6.2.7   | Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule                                                                            | Yes                        | Azure CLI or Powershell  |
| 6.2.8   | Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule                                                                                      | Yes                        | Azure CLI or Powershell  |
| 6.2.9   | Ensure that Activity Log Alert exists for Create or Update Public IP Address rule                                                                              | Yes                        | Azure CLI or Powershell  |
| 6.2.10  | Ensure that Activity Log Alert exists for Delete Public IP Address rule                                                                                        | Yes                        | Azure CLI or Powershell  |
| -       | -                                                                                                                                                              | -                          | -                        |
| 6.3     | Configuring Application Insights                                                                                                                               | -                          | -                        |
| 6.3.1   | Ensure Application Insights are Configured                                                                                                                     | Yes                        | Azure CLI or Powershell  |
| 6.4     | Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it                                                                         | Yes                        | Azure CLI or Powershell  |
| 6.5     | Ensure that SKU Basic/Consumption is not used on artifacts that need to be monitored (Particularly for Production Workloads)                                   | Yes                        | Azure CLI or Powershell  |
| -       | -                                                                                                                                                              | -                          | -                        |
| 7       | Networking                                                                                                                                                     | -                          | -                        |
| 7.1     | Ensure that RDP access from the Internet is evaluated and restricted                                                                                           | Yes                        | Azure CLI                |
| 7.2     | Ensure that SSH access from the Internet is evaluated and restricted                                                                                           | Yes                        | Azure CLI                |
| 7.3     | Ensure that UDP access from the Internet is evaluated and restricted                                                                                           | Yes                        | Azure CLI                |
| 7.4     | Ensure that HTTP(S) access from the Internet is evaluated and restricted                                                                                       | Yes                        | Azure CLI                |
| 7.5     | Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'                                                                         | Yes                        | Azure CLI                |
| 7.6     | Ensure that Network Watcher is 'Enabled' for Azure Regions that are in use                                                                                     | Yes                        | Azure CLI                |
| 7.7     | Ensure that Public IP addresses are Evaluated on a Periodic Basis                                                                                              | Yes                        | Azure CLI                |
| -       | -                                                                                                                                                              | -                          | -                        |
| 8       | Virtual Machines                                                                                                                                               | -                          | -                        |
| 8.1     | Ensure an Azure Bastion Host Exists                                                                                                                            | Yes                        | Azure CLI or Powershell  |
| 8.2     | Ensure Virtual Machines are utilizing Managed Disks                                                                                                            | Yes                        | Powershell               |
| 8.3     | Ensure that 'OS and Data' disks are encrypted with Customer Managed Key (CMK)                                                                                  | Yes                        | Powershell               |
| 8.4     | Ensure that 'Unattached disks' are encrypted with 'Customer Managed Key' (CMK)                                                                                 | Yes                        | Azure CLI                |
| 8.5     | Ensure that 'Disk Network Access' is NOT set to 'Enable public access from all networks'                                                                       | Yes                        | Azure CLI or Powershell  |
| 8.6     | Ensure that 'Enable Data Access Authentication Mode' is 'Checked'                                                                                              | Yes                        | Azure CLI or Powershell  |
| 8.7     | Ensure that Only Approved Extensions Are Installed                                                                                                             | Yes                        | Azure CLI or Powershell  |
| 8.8     | Ensure that Endpoint Protection for all Virtual Machines is installed                                                                                          | Yes                        | Azure CLI or Powershell  |
| 8.9     | [Legacy] Ensure that VHDs are Encrypted                                                                                                                        | Yes                        | Azure CLI or Powershell  |
| 8.10    | Ensure only MFA enabled identities can access privileged Virtual Machine                                                                                       | No                         | -                        |
| 8.11    | Ensure Trusted Launch is enabled on Virtual Machines                                                                                                           | No                         | -                        |
| -       | -                                                                                                                                                              | -                          | -                        |
| 9       | AppService                                                                                                                                                     | -                          | -                        |
| 9.1     | Ensure 'HTTPS Only' is set to 'On'                                                                                                                             | Yes                        | Azure CLI or Powershell  |
| 9.2     | Ensure App Service Authentication is set up for apps in Azure App Service                                                                                      | Yes                        | Azure CLI                |
| 9.3     | Ensure 'FTP State' is set to 'FTPS Only' or 'Disabled'                                                                                                         | Yes                        | Azure CLI or Powershell  |
| 9.4     | Ensure Web App is using the latest version of TLS encryption                                                                                                   | Yes                        | Azure CLI or Powershell  |
| 9.5     | Ensure that Register with Entra ID is enabled on App Service                                                                                                   | Yes                        | Azure CLI or Powershell  |
| 9.6     | Ensure that 'Basic Authentication' is 'Disabled'                                                                                                               | No                         | -                        |
| 9.7     | Ensure that 'PHP version' is currently supported (if in use)                                                                                                   | Yes                        | Azure CLI or Powershell  |
| 9.8     | Ensure that 'Python version' is currently supported (if in use)                                                                                                | Yes                        | Azure CLI or Powershell  |
| 9.9     | Ensure that 'Java version' is currently supported (if in use)                                                                                                  | Yes                        | Azure CLI or Powershell  |
| 9.10    | Ensure that 'HTTP20enabled' is set to 'true' (if in use)                                                                                                       | Yes                        | Azure CLI or Powershell  |
| 9.11    | Ensure Azure Key Vaults are Used to Store Secrets                                                                                                              | Yes                        | Azure CLI or Powershell  |
| 9.12    | Ensure that 'Remote debugging' is set to 'Off'                                                                                                                 | Yes                        | Azure CLI or Powershell  |
| -       | -                                                                                                                                                              | -                          | -                        |
| 10      | Miscellaneous                                                                                                                                                  | -                          | -                        |
| 10.1    | Ensure that Resource Locks are set for Mission-Critical Azure Resources (Manual)                                                                               | Yes                        | Azure CLI or Powershell  |
| -       | -                                                                                                                                                              | -                          | -                        |
| -       | -                                                                                                                                                              | Number of Automatable      | 114                      |
| -       | -                                                                                                                                                              | Number of Non-automatable  | 41                       |
| -       | -                                                                                                                                                              | -                          | -                        |
| -       | -                                                                                                                                                              | Total Number of Controls   | 15                       |

For any controls marked as 'Manual', please refer to the following following at [SAF-CLI](https://saf-cli.mitre.org/) on how to apply manual attestations to the output of an automated assessment. The following [link](https://vmware.github.io/dod-compliance-and-automation/docs/automation-tools/safcli/) that references the SAF-CLI is also useful.

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

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.

## NOTICE

[CIS Benchmarks are published by Center for Internet Security](https://www.cisecurity.org/cis-benchmarks)
