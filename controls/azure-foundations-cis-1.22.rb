control 'azure-foundations-cis-1.22' do
    title 'Ensure That No Custom Subscription Administrator Roles Exist'
    desc "The principle of least privilege should be followed and only necessary privileges should be assigned instead of allowing full administrative access."

    desc 'rationale',
        "Classic subscription admin roles offer basic access management and include Account
        Administrator, Service Administrator, and Co-Administrators. It is recommended the
        least necessary permissions be given initially. Permissions can be added as needed by
        the account holder. This ensures the account holder cannot perform actions which were
        not intended."

    desc 'impact',
        "Subscriptions will need to be handled by Administrators with permissions."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu.
        2. Select Subscriptions.
        3. Select Access control (IAM).
        4. Select Roles.
        5. Click Type and select CustomRole from the drop down menu.
        6. Select View next to a role.
        7. Select JSON.
        8. Check for assignableScopes set to the subscription, and actions set to *.
        9. Repeat steps 6-8 for each custom role.
        From Azure CLI
        List custom roles:
        az role definition list --custom-role-only True
        Check for entries with assignableScope of the subscription, and an action of *
        Page 103
        From PowerShell
        Connect-AzAccount
        Get-AzRoleDefinition |Where-Object {($_.IsCustom -eq $true) -and
        ($_.Actions.contains('*'))}
        Check the output for AssignableScopes value set to the subscription.
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: a451c1ef-c6ca-483d-87ed-f49761e3ffb5 - Name: 'Audit usage of
        custom RBAC roles'"

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu.
        2. Select Subscriptions.
        3. Select Access control (IAM).
        4. Select Roles.
        5. Click Type and select CustomRole from the drop down menu.
        6. Check the box next to each role which grants subscription administrator
        privileges.
        7. Select Remove.
        8. Select Yes.
        From Azure CLI
        List custom roles:
        az role definition list --custom-role-only True
        Check for entries with assignableScope of the subscription, and an action of *.
        To remove a violating role:
        az role definition delete --name <role name>
        Note that any role assignments must be removed before a custom role can be deleted.
        Ensure impact is assessed before deleting a custom role granting subscription
        administrator privileges."

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://docs.microsoft.com/en-us/azure/billing/billing-add-change-azure-subscription-administrator'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-7-follow-just-enough-administration-least-privilege-principle'

    describe 'benchmark' do
        skip 'configure'
    end
end