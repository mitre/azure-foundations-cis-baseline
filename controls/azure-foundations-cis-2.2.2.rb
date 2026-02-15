control 'azure-foundations-cis-2.2.2' do
  title 'Ensure that an exclusionary Geographic Access Policy is considered'
  desc "CAUTION: If these policies are created without first auditing and testing the result,
        misconfiguration can potentially lock out administrators or create undesired access
        issues.
        Conditional Access Policies can be used to block access from geographic locations that
        are deemed out-of-scope for your organization or application. The scope and variables
        for this policy should be carefully examined and defined."

  desc 'rationale',
       "Conditional Access, when used as a deny list for the tenant or subscription, is able to
        prevent ingress or egress of traffic to countries that are outside of the scope of interest
        (e.g.: customers, suppliers) or jurisdiction of an organization. This is an effective way to
        prevent unnecessary and long-lasting exposure to international threats such as APTs."

  desc 'impact',
       "Microsoft Entra ID P1 or P2 is required. Limiting access geographically will deny access
        to users that are traveling or working remotely in a different part of the world. A point-to-
        site or site to site tunnel such as a VPN is recommended to address exceptions to
        geographic access policies."

  desc 'check',
       "Audit from Azure Portal
        1. From Azure Home open the Portal menu in the top left, and select Microsoft
        Entra ID.
        2. Scroll down in the menu on the left, and select Security.
        3. Select on the left side Conditional Access.
        4. Select Policies.
        5. Select the policy you wish to audit, then:
        o Under Assignments > Users, review the users and groups for the
        personnel the policy will apply to
        o Under Assignments > Target resources, review the cloud apps or
        actions for the systems the policy will apply to
        o Under Conditions > Locations, Review the Include locations for those
        that should be blocked
        o Under Conditions > Locations, Review the Exclude locations for those
        that should be allowed (Note: locations set up in the previous
        recommendation for Trusted Location should be in the Exclude list.)
        o Under Access Controls > Grant - Confirm that Block access is
        selected.
        Audit from Azure CLI
        As of this writing there are no subcommands for Conditional Access Policies
        within the Azure CLI
        Audit from PowerShell
        $conditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy
        foreach($policy in $conditionalAccessPolicies) {$policy | Select-Object
        @{N='Policy ID'; E={$policy.id}}, @{N='Included Locations';
        E={$policy.Conditions.Locations.IncludeLocations}}, @{N='Excluded Locations';
        E={$policy.Conditions.Locations.ExcludeLocations}}, @{N='BuiltIn
        GrantControls'; E={$policy.GrantControls.BuiltInControls}}}
        Make sure there is at least 1 row in the output of the above PowerShell command that
        contains Block under the BuiltIn GrantControls column and location IDs under the
        Included Locations and Excluded Locations columns. If not, a policy containing
        these options has not been created and is considered a finding."

  desc 'fix',
       "Remediate from Azure Portal
        Part 1 of 2 - Create the policy and enable it in Report-only mode.
        1. From Azure Home open the portal menu in the top left, and select Microsoft
        Entra ID.
        2. Scroll down in the menu on the left, and select Security.
        3. Select on the left side Conditional Access.
        4. Select Policies.
        5. Click the + New policy button, then:
        6. Provide a name for the policy.
        7. Under Assignments, select Users then:
        o Under Include, select All users
        o Under Exclude, check Users and groups and only select emergency
        access accounts and service accounts (NOTE: Service accounts are
        excluded here because service accounts are non-interactive and cannot
        complete MFA)
        8. Under Assignments, select Target resources then:
        o Under Include, select All cloud apps
        o Leave Exclude blank unless you have a well defined exception
        9. Under Conditions, select Locations then:
        o Select Include, then add entries for locations for those that should be
        blocked
        o Select Exclude, then add entries for those that should be allowed
        (IMPORTANT: Ensure that all Trusted Locations are in the Exclude list.)
        10. Under Access Controls, select Grant select Block Access.
        11. Set Enable policy to Report-only.
        12. Click Create.
        Allow some time to pass to ensure the sign-in logs capture relevant conditional access
        events. These events will need to be reviewed to determine if additional considerations
        are necessary for your organization (e.g. legitimate locations are being blocked and
        investigation is needed for exception).
        NOTE: The policy is not yet 'live,' since Report-only is being used to audit the effect of
        the policy.
        Part 2 of 2 - Confirm that the policy is not blocking access that should be granted, then
        toggle to On.
        1. With your policy now in report-only mode, return to the Microsoft Entra blade and
        click on Sign-in logs.
        2. Review the recent sign-in events - click an event then review the event details
        (specifically the Report-only tab) to ensure:
        o The sign-in event you're reviewing occurred after turning on the policy in
        report-only mode
        o The policy name from step 6 above is listed in the Policy Name column
        o The Result column for the new policy shows that the policy was Not
        applied (indicating the location origin was not blocked)
        3. If the above conditions are present, navigate back to the policy name in
        Conditional Access and open it.
        4. Toggle the policy from Report-only to On.
        5. Click Save.
        Remediate from PowerShell
        First, set up the conditions objects values before updating an existing conditional
        access policy or before creating a new one. You may need to use additional PowerShell
        cmdlets to retrieve specific IDs such as the Get-
        MgIdentityConditionalAccessNamedLocation which outputs the Location IDs for
        use with conditional access policies.
        $conditions = New-Object -TypeName
        Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
        $conditions.Applications = New-Object -TypeName
        Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
        $conditions.Applications.IncludeApplications = <'All' | 'Office365' | 'app
        ID' | @('app ID 1', 'app ID 2', etc...>
        $conditions.Applications.ExcludeApplications = <'Office365' | 'app ID' |
        @('app ID 1', 'app ID 2', etc...)>
        $conditions.Users = New-Object -TypeName
        Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
        $conditions.Users.IncludeUsers = <'All' | 'None' | 'GuestsOrExternalUsers' |
        'Specific User ID' | @('User ID 1', 'User ID 2', etc.)>
        $conditions.Users.ExcludeUsers = <'GuestsOrExternalUsers' | 'Specific User
        ID' | @('User ID 1', 'User ID 2', etc.)>
        $conditions.Users.IncludeGroups = <'group ID' | 'All' | @('Group ID 1',
        'Group ID 2', etc...)>
        $conditions.Users.ExcludeGroups = <'group ID' | @('Group ID 1', 'Group ID 2',
        etc...)>
        $conditions.Users.IncludeRoles = <'Role ID' | 'All' | @('Role ID 1', 'Role ID
        2', etc...)>
        $conditions.Users.ExcludeRoles = <'Role ID' | @('Role ID 1', 'Role ID 2',
        etc...)>
        $conditions.Locations = New-Object -TypeName
        Microsoft.Open.MSGraph.Model.ConditionalAccessLocationCondition
        $conditions.Locations.IncludeLocations = <'Location ID' | @('Location ID 1',
        'Location ID 2', etc...) >
        $conditions.Locations.ExcludeLocations = <'AllTrusted' | 'Location ID' |
        @('Location ID 1', 'Location ID 2', etc...)>
        $controls = New-Object -TypeName
        Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
        $controls._Operator = 'OR'
        $controls.BuiltInControls = 'block'
        Next, update the existing conditional access policy with the condition set options
        configured with the previous commands.
        Update-MgIdentityConditionalAccessPolicy -PolicyId <policy ID> -Conditions
        $conditions -GrantControls $controls
        To create a new conditional access policy that complies with this best practice, run the
        following commands after creating the condition set above
        New-MgIdentityConditionalAccessPolicy -Name 'Policy Name' -State
        <enabled|disabled> -Conditions $conditions -GrantControls $controls"

  impact 0.5
  tag nist: ['AC-2(1)', 'AC-3']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['6.7'] }]

  ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-location'
  ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-report-only'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-7-restrict-resource-access-based-on--conditions'

  client_secret = input('client_secret')
  client_id = input('client_id')
  tenant_id = input('tenant_id')
  included_location_ids = input('included_location_ids')
  excluded_location_ids = input('excluded_location_ids')
  included_location_list = included_location_ids.map { |included_loc| "'#{included_loc}'" }.join(', ')
  excluded_location_list = excluded_location_ids.map { |excluded_loc| "'#{excluded_loc}'" }.join(', ')
  ensure_exclusionary_geographic_policy_script = %(
     $ErrorActionPreference = "Stop"
     $password = ConvertTo-SecureString -String '#{client_secret}' -AsPlainText -Force
     $ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential('#{client_id}',$password)
     Connect-MgGraph -TenantId '#{tenant_id}' -ClientSecretCredential $ClientSecretCredential -NoWelcome
     $included_location_list = @(#{included_location_list}) | ForEach-Object { if ([string]::IsNullOrWhiteSpace($_)) { $null } else { $_ } }
     $excluded_location_list = @(#{excluded_location_list}) | ForEach-Object { if ([string]::IsNullOrWhiteSpace($_)) { $null } else { $_ } }
     $conditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy
      $filteredPolicies = Get-MgIdentityConditionalAccessPolicy | Where-Object {
      $_.GrantControls.BuiltInControls -contains "block" -and
      ($included_location_list -contains $_.Conditions.Locations.IncludeLocations) -and
      ($excluded_location_list -contains $_.Conditions.Locations.ExcludeLocations)
      }

      # Check if $filteredPolicies is not empty and write a message
      if ($filteredPolicies) {
      Write-Output "Pass"
      }
   )

  pwsh_output = powershell(ensure_exclusionary_geographic_policy_script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe 'Ensure at least one Conditional Access Policy' do
    subject { pwsh_output.stdout.strip }
    it 'has Built In Grant Controls setting set to "block" and Included Locations/Excluded Location IDs settings set to appropriate values' do
      expect(subject).to cmp 'Pass'
    end
  end
end
