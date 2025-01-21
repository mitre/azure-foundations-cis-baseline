control 'azure-foundations-cis-2.8' do
    title "Ensure that a Custom Bad Password List is set to 'Enforce' foryour Organization"
    desc "Microsoft Azure provides a Global Banned Password policy that applies to Azure
        administrative and normal user accounts. This is not applied to user accounts that are
        synced from an on-premise Active Directory unless Microsoft Entra ID Connect is used
        and you enable EnforceCloudPasswordPolicyForPasswordSyncedUsers. Please see
        the list in default values on the specifics of this policy. To further password security, it is
        recommended to further define a custom banned password policy."

    desc 'rationale',
        "Enabling this gives your organization further customization on what secure passwords
        are allowed. Setting a bad password list enables your organization to fine-tune its
        password policy further, depending on your needs. Removing easy-to-guess passwords
        increases the security of access to your Azure resources."

    desc 'impact',
        "Increasing needed password complexity might increase overhead on administration of
        user accounts. Licensing requirement for Global Banned Password List and Custom
        Banned Password list requires Microsoft Entra ID P1 or P2. On-premises Active
        Directory Domain Services users that are not synchronized to Microsoft Entra ID also
        benefit from Microsoft Entra ID Password Protection based on existing licensing for
        synchronized users."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID.
        3. Select 'Security'.
        4. Under Manage, select Authentication Methods.
        5. Select Password Protection.
        6. Ensure Enforce custom list is set to Yes.
        7. Scroll through the list to view the enforced passwords."

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Security.
        4. Under Manage, select Authentication Methods.
        5. Select Password Protection.
        6. Set the Enforce custom list option to Yes.
        7. Double click the custom banned password list to add a string."

    impact 0.5
    tag nist: ['IA-5(1)','AC-2(1)','AC-3']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['5.2','6.7'] }]

    ref 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-combined-policy'
    ref 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad'
    ref 'https://docs.microsoft.com/en-us/powershell/module/Azuread/'
    ref 'https://www.microsoft.com/en-us/research/publication/password-guidance/'
    ref 'https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-configure-custom-password-protection'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-6-use-strong-authentication-controls'

    describe 'benchmark' do
        skip 'configure'
    end
end