control 'azure-foundations-cis-1.14' do
    title "Ensure That 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects' "
    desc "Limit guest user permissions."

    desc 'rationale',
        "Limiting guest access ensures that guest accounts do not have permission for certain
        directory tasks, such as enumerating users, groups or other directory resources, and
        cannot be assigned to administrative roles in your directory. Guest access has three
        levels of restriction.
        1. Guest users have the same access as members (most inclusive),
        2. Guest users have limited access to properties and memberships of directory
        objects (default value),
        3. Guest user access is restricted to properties and memberships of their own
        directory objects (most restrictive).
        The recommended option is the 3rd, most restrictive: 'Guest user access is restricted to
        their own directory object'."

    desc 'impact',
        "This may create additional requests for permissions to access resources that
        administrators will need to approve.
        According to https://learn.microsoft.com/en-us/azure/active-directory/enterprise-
        users/users-restrict-guest-permissions#services-currently-not-supported
        Service without current support might have compatibility issues with the new guest
        restriction setting.
        • Forms
        • Project
        • Yammer
        • Planner in SharePoint"

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Then External Identities
        4. Select External collaboration settings
        5. Under Guest user access, ensure that Guest user access restrictions is set
        to Guest user access is restricted to properties and memberships of
        their own directory objects
        From PowerShell
        1. Enter the following Get-AzureADMSAuthorizationPolicy
        Which will give a result like:
        Id : authorizationPolicy
        OdataType :
        Description : Used to manage
        authorization related settings across the company.
        DisplayName : Authorization Policy
        EnabledPreviewFeatures : {}
        GuestUserRoleId : 10dae51f-b6af-4016-8d66-
        8c2a99b929b3
        PermissionGrantPolicyIdsAssignedToDefaultUserRole : {user-default-legacy}
        If the GuestUserRoleID property does not equal 2af84b1e-32c8-42b7-82bc-
        daa82404023b then it is not set to most restrictive."

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Then External Identities
        4. Select External collaboration settings
        5. Under Guest user access, change Guest user access restrictions to be Guest
        user access is restricted to properties and memberships of their own
        directory objects
        From PowerShell
        1. From a PowerShell session enter Set-AzureADMSAuthorizationPolicy -
        GuestUserRoleId '2af84b1e-32c8-42b7-82bc-daa82404023b'
        2. Check that the setting was applied by entering Get-
        AzureADMSAuthorizationPolicy
        3. Make certain that the GuestUserRoleId is equal to the earlier entered value of
        2af84b1e-32c8-42b7-82bc-daa82404023b."

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions#member-and-guest-users'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions'

    describe 'benchmark' do
        skip 'configure'
    end
end