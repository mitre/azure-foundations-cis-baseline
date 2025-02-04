control 'azure-foundations-cis-2.2.6' do
    title 'Ensure Multi-factor Authentication is Required for Risky Sign-ins'
    desc "Entra ID tracks the behavior of sign-in events. If the Entra ID domain is licensed with
        P2, the sign-in behavior can be used as a detection mechanism for additional scrutiny
        during the sign-in event. If this policy is set up, then Risky Sign-in events will prompt
        users to use multi-factor authentication (MFA) tokens on login for additional verification."

    desc 'rationale',
        "Enabling multi-factor authentication is a recommended setting to limit the potential of
        accounts being compromised and limiting access to authenticated personnel. Enabling
        this policy allows Entra ID's risk-detection mechanisms to force additional scrutiny on
        the login event, providing a deterrent response to potentially malicious sign-in events,
        and adding an additional authentication layer as a reaction to potentially malicious
        behavior."

    desc 'impact',
        "Risk Policies for Conditional Access require Microsoft Entra ID P2. Additional overhead
        to support or maintain these policies may also be required if users lose access to their
        MFA tokens."

    desc 'check',
       "Audit from Azure Portal
        1. From Azure Home select the Portal Menu in the top left and select Microsoft
        Entra ID.
        2. Select Security.
        3. Select on the left side Conditional Access.
        4. Select Policies.
        5. Select the policy you wish to audit.
        6. Click the blue text under Users.
        7. View under Include the corresponding users and groups to whom the policy is
        applied.
        8. View under Exclude to determine which users and groups to whom the policy is
        not applied."

    desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu in the top left and select Microsoft
        Entra ID.
        2. Select Security
        3. Select Conditional Access.
        4. Select Policies.
        5. Click + New policy.
        6. Enter a name for the policy.
        7. Click the blue text under Users.
        8. Under Include, select All users.
        9. Under Exclude, check Users and groups.
        10. Select users this policy should not apply to and click Select.
        11. Click the blue text under Target resources.
        12. Select All cloud apps.
        13. Click the blue text under Conditions.
        14. Select Sign-in risk.
        15. Update the Configure toggle to Yes.
        16. Check the sign-in risk level this policy should apply to, e.g. High and Medium.
        17. Select Done.
        18. Click the blue text under Grant and check Require multifactor
        authentication then click the Select button.
        19. Click the blue text under Session then check Sign-in frequency and select
        Every time and click the Select button.
        20. Set Enable policy to Report-only.
        21. Click Create.
        After testing the policy in report-only mode, update the Enable policy setting from
        Report-only to On."

    impact 0.5
    tag nist: ['IA-2(1)','IA-2(2)','AC-19','AC-2(1)','AC-3']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['6.3','6.4','6.7'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/troubleshoot-conditional-access-what-if'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-insights-reporting'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-7-restrict-resource-access-based-on--conditions'

    describe 'Ensure Multi-factor Authentication is Required for Risky Sign-ins' do
        skip 'The check for this control needs to be done manually'
    end
end