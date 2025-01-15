control 'azure-foundations-cis-1.1.1' do
    title "Ensure that 'Multi-Factor Auth Status' is 'Enabled' for allPrivileged Users"
    desc "Enable multi-factor authentication for all roles, groups, and users that have write access
        or permissions to Azure resources. These include custom created objects or built-in
        roles such as;
        • Service Co-Administrators
        • Subscription Owners
        • Contributors"

    desc 'rationale',
        "Multi-factor authentication requires an individual to present a minimum of two separate
        forms of authentication before access is granted. Multi-factor authentication provides
        additional assurance that the individual attempting to gain access is who they claim to
        be. With multi-factor authentication, an attacker would need to compromise at least two
        different authentication mechanisms, increasing the difficulty of compromise and thus
        reducing the risk."

    desc 'impact',
        "Users would require two forms of authentication before any access is granted.
        Additional administrative time will be required for managing dual forms of authentication
        when enabling multi-factor authentication."


    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select the Microsoft Entra ID blade
        3. Select Users
        4. Take note of all users with the role Service Co-Administrators, Owners or
        Contributors
        5. Click on the Per-User MFA button in the top row menu
        6. Ensure that MULTI-FACTOR AUTH STATUS is Enabled for all noted users
        From REST API
        For Every Subscription, For Every Tenant
        Step 1: Identify Users with Administrative Access
        Page 24
        1. List All Users Using Microsoft Graph API:
        GET https://graph.microsoft.com/v1.0/users
        Capture id and corresponding userPrincipalName ('$uid', '$userPrincipalName')
        2. List all Role Definitions Using Azure management API:
        https://management.azure.com/subscriptions/:subscriptionId/providers/Microsof
        t.Authorization/roleDefinitions?api-version=2017-05-01
        Capture Role Definition IDs/Name ('$name') and role names ('$properties/roleName')
        where 'properties/roleName' contains (Owner or *contributor or admin )
        3. List All Role Assignments (Mappings $A.uid to $B.name) Using Azure
        Management API:
        GET
        https://management.azure.com/subscriptions/:subscriptionId/providers/Microsof
        t.Authorization/roleassignments?api-version=2017-10-01-preview
        Find all administrative roles ($B.name) in 'Properties/roleDefinitionId' mapped with
        user ids ($A.id) in 'Properties/principalId' where 'Properties/principalType' ==
        'User'
        4. Now Match ($CProperties/principalId) with $A.uid and get
        $A.userPrincipalName save this as D.userPrincipalName
        Step 2: Run MSOL PowerShell command:
        Get-MsolUser -All | where {$_.StrongAuthenticationMethods.Count -eq 0} |
        Select-Object -Property UserPrincipalName
        If the output contains any of the $D.userPrincipalName, then this recommendation is
        non-compliant.
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: e3e008c3-56b9-4133-8fd7-d3347377402a - Name: 'Accounts with
        owner permissions on Azure resources should be MFA enabled'
        • Policy ID: 931e118d-50a1-4457-a5e4-78550e086c52 - Name: 'Accounts with
        write permissions on Azure resources should be MFA enabled'"

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID blade
        3. Select Users
        4. Take note of all users with the role Service Co-Administrators, Owners or
        Contributors
        5. Click on the Per-User MFA button in the top row menu
        6. Check the box next to each noted user
        7. Click Enable under quick steps in the right-hand panel
        8. Click enable multi-factor auth
        9. Click close
        Other Options within Azure Portal
        Follow Microsoft Azure documentation and enable multi-factor authentication in your
        environment.
        https://docs.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-
        azure-mfa
        Enabling and configuring MFA with conditional access policy is a multi-step process.
        Here are some additional resources on the process within Entra ID to enable multi-
        factor authentication for users within your subscriptions with conditional access policy.
        https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-
        conditional-access-policy-admin-mfa
        https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-
        getstarted#enable-multi-factor-authentication-with-conditional-access
        https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-
        mfasettings"

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://docs.microsoft.com/en-us/azure/multi-factor-authentication/multi-factor-authentication'
    ref 'https://stackoverflow.com/questions/41156206/azure-active-directory-premium-mfa-attributes-via-graph-api' 
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-4-authenticate-server-and-services'

    describe 'benchmark' do
        skip 'configure'
    end
end