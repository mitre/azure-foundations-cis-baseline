control 'azure-foundations-cis-2.16' do
    title "Ensure that 'Guest invite restrictions' is set to 'Only users assigned to specific admin roles can invite guest users'"
    desc "Restrict invitations to users with specific administrative roles only."

    desc 'rationale',
        "Restricting invitations to users with specific administrator roles ensures that only
        authorized accounts have access to cloud resources. This helps to maintain 'Need to
        Know' permissions and prevents inadvertent access to data.
        By default the setting Guest invite restrictions is set to Anyone in the
        organization can invite guest users including guests and non-admins. This would
        allow anyone within the organization to invite guests and non-admins to the tenant,
        posing a security risk."

    desc 'impact',
        "With the option of Only users assigned to specific admin roles can invite guest
        users selected, users with specific admin roles will be in charge of sending invitations to
        the external users, requiring additional overhead by them to manage user accounts.
        This will mean coordinating with other departments as they are onboarding new users."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Then External Identities
        4. External collaboration settings
        5. Under Guest invite settings, for Guest invite restrictions, ensure that that
        Only users assigned to specific admin roles can invite guest users is
        selected
        Note: This setting has 4 levels of restriction, which include:
        • Anyone in the organization can invite guest users including guests and non-
        admins (most inclusive),
        • Member users and users assigned to specific admin roles can invite guest users
        including guests with member permissions,
        • Only users assigned to specific admin roles can invite guest users,
        • No one in the organization can invite guest users including admins (most
        restrictive)."

    desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select External Identities
        4. Select External collaboration settings
        5. Under Guest invite settings, set Guest invite restrictions, to Only
        users assigned to specific admin roles can invite guest users
        6. Click Save
        Remediate from PowerShell
        Enter the following:
        Connect-MgGraph
        Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom 'adminsAndGuestInviters'"

    impact 0.5
    tag nist: ['IA-4','IA-5','AC-1','AC-2','AC-2(1)','AC-2','AC-5','AC-6','AC-6(1)','AC-6(7)','AU-9(4)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['6.1','6.8'] }]
    
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-b2b-delegate-invitations'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements'

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end