control 'azure-foundations-cis-2.1.2' do
  title "Ensure that 'Multi-Factor Auth Status' is 'Enabled' for allPrivileged Users"
  desc "[IMPORTANT - Please read the section overview: If your organization pays for
        Microsoft Entra ID licensing (included in Microsoft 365 E3, E5, or F5, and EM&S E3 or
        E5 licenses) and CAN use Conditional Access, ignore the recommendations in this
        section and proceed to the Conditional Access section.]
        Enable multi-factor authentication for all roles, groups, and users that have write access
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
       "Audit from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select the Microsoft Entra ID blade
        3. Under Manage, click Roles and administrators
        4. Take note of all users with the role Service Co-Administrators, Owners or
        Contributors
        5. Return to the Overview
        6. Under Manage, click Users
        7. Click on the Per-User MFA button in the top row menu
        8. Ensure that Status is Enabled for all noted users
        Audit from REST API
        For Every Subscription, For Every Tenant
        Step 1: Identify Users with Administrative Access
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
        Find all administrative roles ($B.name) in 'Properties/roleDefinitionId' mapped
        with user ids ($A.id) in 'Properties/principalId' where
        'Properties/principalType' == 'User'
        4. Now Match ($CProperties/principalId) with $A.uid and get
        $A.userPrincipalName save this as D.userPrincipalName
        Step 2: Run Graph PowerShell command:
        get-mguser -All | where {$_.StrongAuthenticationMethods.Count -eq 0} |
        Select-Object -Property UserPrincipalName
        If the output contains any of the $D.userPrincipalName, then this recommendation is
        non-compliant.
        Audit from Azure Policy
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
        9. Click close"

  impact 0.5
  tag nist: ['IA-2(1)', 'IA-2(2)', 'AC-19', 'IA-2(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['6.3', '6.4', '6.5'] }]

  ref 'https://docs.microsoft.com/en-us/azure/multi-factor-authentication/multi-factor-authentication'
  ref 'https://stackoverflow.com/questions/41156206/azure-active-directory-premium-mfa-attributes-via-graph-api'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-4-authenticate-server-and-services'

  subscription_id = input('subscription_id')
  graph_token_cmd = 'az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv'
  graph_token = command(graph_token_cmd).stdout.strip

  management_token_cmd = 'az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv'
  management_token = command(management_token_cmd).stdout.strip

  graph_users = http('https://graph.microsoft.com/v1.0/users',
                    method: 'GET',
                    headers: { 'Authorization' => "Bearer #{graph_token}" })

  role_defs = http("https://management.azure.com/subscriptions/#{subscription_id}/providers/Microsoft.Authorization/roleDefinitions?api-version=2017-05-01",
                    method: 'GET',
                    headers: { 'Authorization' => "Bearer #{management_token}" })

  role_assignments = http("https://management.azure.com/subscriptions/#{subscription_id}/providers/Microsoft.Authorization/roleassignments?api-version=2017-10-01-preview",
                            method: 'GET',
                            headers: { 'Authorization' => "Bearer #{management_token}" })

  users = JSON.parse(graph_users.body)['value']

  role_definitions = JSON.parse(role_defs.body)['value']
  admin_role_ids = role_definitions.select do |role|
    role['properties']['roleName'].match?(/(Owner|Contributor|Admin)/i)
  end.map { |role| role['id'] }

  assignments = JSON.parse(role_assignments.body)['value']
  admin_user_ids = assignments.select do |assignment|
    assignment['properties']['principalType'] == 'User' &&
      admin_role_ids.include?(assignment['properties']['roleDefinitionId'])
  end.map { |assignment| assignment['properties']['principalId'] }

  non_compliant_admins = users.select do |user|
    admin_user_ids.include?(user['id']) &&
      (user['StrongAuthenticationMethods'].nil? || user['StrongAuthenticationMethods'].empty?)
  end.map { |user| user['userPrincipalName'] }

  describe 'Administrative users without MFA' do
    it 'should be empty (i.e. every admin has MFA enabled)' do
      expect(non_compliant_admins).to be_empty
    end
  end
end
