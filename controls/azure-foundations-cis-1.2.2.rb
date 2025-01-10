control 'azure-foundations-cis-1.1.1' do
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
       "From Azure Portal
        1. From Azure Home open the Portal menu in the top left, and select Microsoft
        Entra ID.
        2. Scroll down in the menu on the left, and select Security.
        3. Select on the left side Conditional Access.
        4. Select the policy you wish to audit, then:
        o Under Assignments, Review the Users and Groups for the personnel the
        policy will apply to
        o Under Assignments, Review the Cloud apps or actions for the systems
        the policy will apply to
        o Under Conditions, Review the Include locations for those that should be
        blocked
        Page 37
        o Under Conditions, Review the Exclude locations for those that should be
        allowed (Note: locations set up in the previous recommendation for
        Trusted Location should be in the Exclude list.)
        o Under Access Controls > Grant - Confirm that Block Access is selected.
        From Azure CLI
        As of this writing there are no subcommands for Conditional Access Policies within the
        Azure CLI
        From PowerShell
        $conditionalAccessPolicies = Get-AzureADMSConditionalAccessPolicy
        foreach($policy in $conditionalAccessPolicies) {$policy | Select-Object
        @{N='Policy ID'; E={$policy.id}}, @{N='Included Locations';
        E={$policy.Conditions.Locations.IncludeLocations}}, @{N='Excluded Locations';
        E={$policy.Conditions.Locations.ExcludeLocations}}, @{N='BuiltIn
        GrantControls'; E={$policy.GrantControls.BuiltInControls}}}
        Make sure there is at least 1 row in the output of the above PowerShell command that
        contains Block under the BuiltIn GrantControls column and location IDs under the
        Included Locations and Excluded Locations columns. If not, a policy containing these
        options has not been created and is considered a finding"

    desc 'fix',
       "From Azure Portal
        Part 1 of 2 - Create the policy and enable it in Report-only mode.
        1. From Azure Home open the portal menu in the top left, and select Microsoft
        Entra ID.
        2. Scroll down in the menu on the left, and select Security.
        3. Select on the left side Conditional Access.
        4. Click the + New policy button, then:
        5. Provide a name for the policy.
        6. Under Assignments, select Users or workload identities then:
        o Under Include, select All users
        o Under Exclude, check Users and groups and only select emergency
        access accounts and service accounts (NOTE: Service accounts are
        excluded here because service accounts are non-interactive and cannot
        complete MFA)
        7. Under Assignments, select Cloud apps or actions then:
        o Under Include, select All cloud apps
        o Leave Exclude blank unless you have a well defined exception
        8. Under Conditions, select Locations then:
        o Select Include, then add entries for locations for those that should be
        blocked
        o Select Exclude, then add entries for those that should be allowed
        (IMPORTANT: Ensure that all Trusted Locations are in the Exclude list.)
        Page 38
        9. Under Access Controls, select Grant and Confirm that Block Access is selected.
        10. Set Enable policy to Report-only.
        11. Click Create.
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
        o The policy name from step 5 above is listed in the Policy Name column
        o The Result column for the new policy shows that the policy was Not
        applied (indicating the location origin was not blocked)
        3. If the above conditions are present, navigate back to the policy name in
        Conditional Access and open it.
        4. Toggle the policy from Report-only to On.
        5. Click Save.
        From PowerShell
        First, set up the conditions objects values before updating an existing conditional
        access policy or before creating a new one. You may need to use additional PowerShell
        cmdlets to retrieve specific IDs such as the Get-AzureADMSNamedLocationPolicy which
        outputs the Location IDs for use with conditional access policies.
        Page 39
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
        Set-AzureADMSConditionalAccessPolicy -PolicyId <policy ID> -Conditions
        $conditions -GrantControls $controls
        To create a new conditional access policy that complies with this best practice, run the
        following commands after creating the condition set above
        New-AzureADMSConditionalAccessPolicy -Name 'Policy Name' -State
        <enabled|disabled> -Conditions $conditions -GrantControls $controls"

    impact 0.5
    tag nist: ['check NIST SP 800-53, Revision 5']
    tag severity: 'low, medium, or high '
    tag cis_controls: [{ '8.1' => ['check cis controls navigator'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-location'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-report-only'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-7-restrict-resource-access-based-on--conditions'

    describe 'benchmark' do
        skip 'configure'
    end
end