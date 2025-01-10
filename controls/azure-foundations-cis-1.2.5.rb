control 'azure-foundations-cis-1.1.1' do
    title 'Ensure Multi-factor Authentication is Required for Risky Sign-ins'
    desc "For designated users, they will be prompted to use their multi-factor authentication (MFA) process on login."

    desc 'rationale',
        "Enabling multi-factor authentication is a recommended setting to limit the potential of accounts being compromised and limiting access to authenticated personnel."

    desc 'impact',
        "There is an increased cost, as Conditional Access policies require Microsoft Entra ID P1
        or P2. Similarly, they may require additional overhead to maintain if users lose access
        to their MFA."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu in the top left, and select Microsoft
        Entra ID.
        2. Select Security.
        3. Select on the left side Conditional Access.
        4. Select the policy you wish to audit.
        5. View under Users and Groups the corresponding users and groups to whom the
        policy is applied.
        6. View under Exclude to determine which users and groups to whom the policy is
        not applied."

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu in the top left, and select Microsoft
        Entra ID.
        2. Select Security
        3. Select Conditional Access.
        4. Click + New policy.
        5. Enter a name for the policy.
        6. Select Users or workload identities.
        Page 48
        7. Under Include, select All users.
        8. Under Exclude, check Users and groups.
        9. Select users this policy should not apply to and click Select.
        10. Select Cloud apps or actions.
        11. Select All cloud apps.
        12. Select Conditions.
        13. Select Sign-in risk.
        14. Update the Configure toggle to Yes.
        15. Check the sign-in risk level this policy should apply to, e.g. High and Medium.
        16. Select Done.
        17. Click the blue text under Grant access and check Require multifactor
        authentication then click the Select button.
        18. Click the blue text under Session then check Sign-in frequency and select
        Every time and click the Select button.
        19. Set Enable policy to Report-only.
        20. Click Create.
        After testing the policy in report-only mode, update the Enable policy setting from
        Report-only to On"

    impact 0.5
    tag nist: ['check NIST SP 800-53, Revision 5']
    tag severity: 'low, medium, or high '
    tag cis_controls: [{ '8.1' => ['check cis controls navigator'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/troubleshoot-conditional-access-what-if'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-insights-reporting'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-7-restrict-resource-access-based-on--conditions'

    describe 'benchmark' do
        skip 'configure'
    end
end