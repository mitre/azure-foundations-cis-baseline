control 'azure-foundations-cis-2.24' do
    title 'Ensure a Custom Role is Assigned Permissions for Administering Resource Locks'
    desc "Resource locking is a powerful protection mechanism that can prevent inadvertent
        modification/deletion of resources within Azure subscriptions/Resource Groups and is a
        recommended NIST configuration."

    desc 'rationale',
        "Given the resource lock functionality is outside of standard Role Based Access
        Control(RBAC), it would be prudent to create a resource lock administrator role to
        prevent inadvertent unlocking of resources."

    desc 'impact',
        "By adding this role, specific permissions may be granted for managing just resource
        locks rather than needing to provide the wide Owner or User Access Administrator role,
        reducing the risk of the user being able to do unintentional damage."

    desc 'check',
       "From Azure Portal
        1. In the Azure portal, open a subscription or resource group where you want to
        view assigned roles.
        2. Select Access control (IAM)
        3. Select Roles
        4. Search for the custom role named <role_name> Ex. from remediation Resource
        Lock Administrator
        5. Ensure that the role is assigned to the appropriate users."

    desc 'fix',
       "From Azure Portal
        1. In the Azure portal, open a subscription or resource group where you want the
        custom role to be assigned.
        2. Select Access control (IAM).
        3. Click Add.
        4. Select Add custom role.
        5. In the Custom Role Name field enter Resource Lock Administrator.
        6. In the Description field enter Can Administer Resource Locks.
        Page 106
        7. For Baseline permissions select Start from scratch
        8. Select next.
        9. In the Permissions tab select Add permissions.
        10. In the Search for a permission box, type in Microsoft.Authorization/locks to
        search for permissions.
        11. Select the check box next to the permission Microsoft.Authorization/locks.
        12. Select Add.
        13. Select Review + create.
        14. Select Create.
        15. Assign the newly created role to the appropriate user.
        From PowerShell:
        Below is a power shell definition for a resource lock administrator role created at an
        Azure Management group level
        Import-Module Az.Accounts
        Connect-AzAccount
        $role = Get-AzRoleDefinition 'User Access Administrator'
        $role.Id = $null
        $role.Name = 'Resource Lock Administrator'
        $role.Description = 'Can Administer Resource Locks'
        $role.Actions.Clear()
        $role.Actions.Add('Microsoft.Authorization/locks/*')
        $role.AssignableScopes.Clear()
        * Scope at the Management group level Management group
        $role.AssignableScopes.Add('/providers/Microsoft.Management/managementGroups/
        MG-Name')
        New-AzRoleDefinition -Role $role
        Get-AzureRmRoleDefinition 'Resource Lock Administrator'"

    impact 0.5
    tag nist: ['AC-3','AC-5','AC-6','MP-2','AC-2','AC-5','AC-6','AC-6(1)','AC-6(7)','AU-9(4)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['3.3','6.8'] }]

    ref 'https://docs.microsoft.com/en-us/azure/role-based-access-control/custom-roles'
    ref 'https://docs.microsoft.com/en-us/azure/role-based-access-control/check-access'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-7-follow-just-enough-administration-least-privilege-principle'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'

    describe 'benchmark' do
        skip 'configure'
    end
end