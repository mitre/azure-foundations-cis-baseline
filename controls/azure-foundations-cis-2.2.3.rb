control 'azure-foundations-cis-2.2.3' do
    title 'Ensure that an exclusionary Device code flow policy is considered'
    desc "Conditional Access Policies can be used to prevent the Device code authentication flow.
        Device code flow should be permitted only for users that regularly perform duties that
        explicitly require the use of Device Code to authenticate, such as utilizing Azure with
        PowerShell."

    desc 'rationale',
        "Attackers use Device code flow in phishing attacks and, if successful, results in the
        attacker gaining access tokens and refresh tokens which are scoped to
        'user_impersonation', which can perform any action the user has permission to
        perform."

    desc 'impact',
        "Microsoft Entra ID P1 or P2 is required.
        This policy should be tested using the Report-only mode before implementation.
        Without a full and careful understanding of the accounts and personnel who require
        Device code authentication flow, implementing this policy can block authentication for
        users and devices who rely on Device code flow. For users and devices that rely on
        device code flow authentication, more secure alternatives should be implemented
        wherever possible."

    desc 'check',
       "Audit from Azure Portal
        1. From Azure Home open the Portal menu in the top left and select Microsoft
        Entra ID.
        2. Scroll down in the menu on the left and select Security.
        3. Select on the left side Conditional Access.
        4. Select Policies.
        5. Select the policy you wish to audit, then:
        o Under Assignments > Users, review the users and groups for the
        personnel the policy will apply to
        o Under Assignments > Target resources, review the cloud apps or
        actions for the systems the policy will apply to
        o Under Conditions > Authentication Flows, review the configuration to
        ensure Device code flow is selected
        o Under Access Controls > Grant - Confirm that Block access is
        selected."

    desc 'fix',
       "Remediate from Azure Portal
        Part 1 of 2 - Create the policy and enable it in Report-only mode.
        1. From Azure Home open the portal menu in the top left and select Microsoft
        Entra ID.
        2. Scroll down in the menu on the left and select Security.
        3. Select on the left side Conditional Access.
        4. Select Policies.
        5. Click the + New policy button, then:
        6. Provide a name for the policy.
        7. Under Assignments, select Users then:
        o Under Include, select All users
        o Under Exclude, check Users and groups and only select emergency
        access accounts
        8. Under Assignments, select Target resources then:
        o Under Include, select All cloud apps
        o Leave Exclude blank unless you have a well defined exception
        9. Under Conditions > Authentication Flows, set Configure to Yes then:
        o Select Device code flow
        o Select Done
        10. Under Access Controls > Grant, select Block Access.
        11. Set Enable policy to Report-only.
        12. Click Create.
        Allow some time to pass to ensure the sign-in logs capture relevant conditional access
        events. These events will need to be reviewed to determine if additional considerations
        are necessary for your organization (e.g. many legitimate use cases of device code
        authentication are observed).
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
        applied (indicating the device code authentication flow was not blocked)
        3. If the above conditions are present, navigate back to the policy name in
        Conditional Access and open it.
        4. Toggle the policy from Report-only to On.
        5. Click Save."

    impact 0.5
    tag nist: ['IA-4','IA-5','AC-1','AC-2','AC-2(1)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['6.1'] }]

    ref 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows#device-code-flow'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-7-restrict-resource-access-based-on--conditions'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-report-only'
    ref 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-authentication-flows'

    describe 'Ensure that an exclusionary Device code flow policy is considered' do
        skip 'The check for this control needs to be done manually'
    end
end