control 'azure-foundations-cis-8.10' do
    title 'Ensure only MFA enabled identities can access privileged Virtual Machine'
    desc "Verify identities without MFA that can log in to a privileged virtual machine using separate login credentials. An adversary can leverage the access to move laterally and perform actions with the virtual machine's managed identity. Make sure the virtual machine only has necessary permissions, and revoke the admin-level permissions according to the least privileges principal"

    desc 'rationale',
        "Integrating multi-factor authentication (MFA) as part of the organizational policy can greatly reduce the risk of an identity gaining control of valid credentials that may be used for additional tactics such as initial access, lateral movement, and collecting information. MFA can also be used to restrict access to cloud resources and APIs.
        An Adversary may log into accessible cloud services within a compromised environment using Valid Accounts that are synchronized to move laterally and perform actions with the virtual machine's managed identity. The adversary may then perform management actions or access cloud-hosted resources as the logged-on managed identity."

    desc 'impact',
        'This recommendation requires an Azure AD P2 License to implement.
        Ensure that identities that are provisioned to a virtual machine utilizes an RBAC/ABAC group and is allocated a role using Azure PIM, and the Role settings require MFA or use another PAM solution (like CyberArk) for accessing Virtual Machines.'
    
    desc 'check',
       "Audit from Azure Portal
            1. Log in to the Azure portal.
            2. Select the Subscription, then click on Access control (IAM).
            3. Select Role Assignments from the top menu and apply filters on Assignment type as Privileged administrator roles and Type as Virtual Machines.
            4. Verify the list of privileged managed identities attached to any virtual machine.
            5. If there are privileged managed identities from the above list, then check the list of users without MFA by navigating to Azure AD.
            6. In the left navigation pane select Users from Manage.
            7. Click on Per-User MFA from the top menu options and for each user with MULTI-FACTOR AUTH STATUS as Disabled follow the below-mentioned steps:
                o Select the Subscription, then click on Access control (IAM).
                o Select Check access and click on User, group, or service principal.
                o Enter the user name or email and verify there are no role assignments on the user that provides access like Virtual Machine Administrator Login or Virtual Machine User Login. Make sure this follows the least privileges principal."

    desc 'fix',
       "Remediate from Azure Portal
            1. Log in to the Azure portal.
            2. This can be remediated by enabling MFA for user, Removing user access or Reducing access of managed identities attached to virtual machines.
                • Case I : Enable MFA for users having access on virtual machines.
                    1. Navigate to Azure AD from the left pane and select Users from the Manage section.
                    2. Click on Per-User MFA from the top menu options and select each user with MULTI-FACTOR AUTH STATUS as Disabled and can login to virtual machines:
                        ▪ From quick steps on the right side select enable.
                        ▪ Click on enable multi-factor auth and share the link with the user to setup MFA as required.
                • Case II : Removing user access on a virtual machine.
                    1. Select the Subscription, then click on Access control (IAM).
                    2. Select Role assignments and search for Virtual Machine Administrator Login or Virtual Machine User Login or any role that provides access to log into virtual machines.
                    3. Click on Role Name, Select Assignments, and remove identities with no MFA configured.
                • Case III : Reducing access of managed identities attached to virtual machines.
                    1. Select the Subscription, then click on Access control (IAM).
                    2. Select Role Assignments from the top menu and apply filters on Assignment type as Privileged administrator roles and Type as Virtual Machines.
                    3. Click on Role Name, Select Assignments, and remove identities access make sure this follows the least privileges principal."

    impact 0.5
    tag nist: ['IA-2(1)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['6.5'] }]

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end