control 'azure-foundations-cis-1.15' do
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
        Page 88
        • Only users assigned to specific admin roles can invite guest users,
        • No one in the organization can invite guest users including admins (most
        restrictive)."

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Then External Identities
        4. Select External collaboration settings
        5. Under Guest invite settings, for Guest invite restrictions, ensure that Only
        users assigned to specific admin roles can invite guest users is selected"

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]
    
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-b2b-delegate-invitations'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements'

    describe 'benchmark' do
        skip 'configure'
    end
end