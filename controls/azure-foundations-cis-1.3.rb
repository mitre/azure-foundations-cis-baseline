control 'azure-foundations-cis-1.1.1' do
    title "Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'"
    desc "Require administrators or appropriately delegated users to create new tenants."

    desc 'rationale',
        "It is recommended to only allow an administrator to create new tenants. This prevent
        users from creating new Microsoft Entra ID or Azure AD B2C tenants and ensures that
        only authorized users are able to do so."

    desc 'impact',
        "Enforcing this setting will ensure that only authorized users are able to create new tenants."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Users
        4. Select User settings
        5. Ensure that Restrict non-admin users from creating tenants is set to Yes
        From PowerShell
        Import-Module Microsoft.Graph.Identity.SignIns
        Connect-MgGraph -Scopes 'Policy.ReadWrite.Authorization'
        Get-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty
        DefaultUserRolePermissions | Format-List
        Review the 'DefaultUserRolePermissions' section of the output. Ensure that
        AllowedToCreateTenants is not 'True'."

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Users
        4. Select User settings
        Page 57
        5. Set Restrict non-admin users from creating tenants to Yes
        From PowerShell
        Import-Module Microsoft.Graph.Identity.SignIns
        Connect-MgGraph -Scopes 'Policy.ReadWrite.Authorization'
        Select-MgProfile -Name beta
        $params = @{
        DefaultUserRolePermissions = @{
        AllowedToCreateTenants = $false
        }
        }
        Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId -BodyParameter
        $params"

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions'
    ref 'https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#tenant-creator'
    ref 'https://blog.admindroid.com/disable-users-creating-new-azure-ad-tenants-in-microsoft-365/'

    describe 'benchmark' do
        skip 'configure'
    end
end