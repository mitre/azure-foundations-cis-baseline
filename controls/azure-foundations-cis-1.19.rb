control 'azure-foundations-cis-1.19' do
    title "Ensure that 'Owners can manage group membership requests in the Access Panel' is set to 'No'"
    desc "Restrict security group management to administrators only."

    desc 'rationale',
        "Restricting security group management to administrators only prohibits users from
        making changes to security groups. This ensures that security groups are appropriately
        managed and their management is not delegated to non-administrators."

    desc 'impact',
        "Group Membership for user accounts will need to be handled by Admins and cause
        administrative overhead."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Then Groups
        4. Select General in settings
        5. Ensure that Owners can manage group membership requests in the Access
        Panel is set to No"

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Then Groups
        4. Select General in settings
        5. Set Owners can manage group membership requests in the Access Panel to No"

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-accessmanagement-self-service-group-management#making-a-group-available-for-end-user-self-service'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-8-determine-access-process-for-cloud-provider-support'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'

    describe 'benchmark' do
        skip 'configure'
    end
end