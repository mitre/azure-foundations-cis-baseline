control 'azure-foundations-cis-1.2.4' do
    title 'Ensure that A Multi-factor Authentication Policy Exists for All Users'
    desc "For designated users, they will be prompted to use their multi-factor authentication (MFA) process on logins."

    desc 'rationale',
        "Enabling multi-factor authentication is a recommended setting to limit the potential of accounts being compromised and limiting access to authenticated personnel."

    desc 'impact',
        "There is an increased cost, as Conditional Access policies require Microsoft Entra ID P1
        or P2. Similarly, this may require additional overhead to maintain if users lose access to
        their MFA."

    desc 'check',
       "From Azure Portal
        1. From Azure Home open the Portal Menu in the top left, and select Microsoft
        Entra ID.
        2. Scroll down in the menu on the left, and select Security.
        3. Select on the left side Conditional Access.
        4. Select the policy you wish to audit.
        5. View under Users and Groups the corresponding users and groups to whom the
        policy is applied.
        6. View under Exclude to determine which users and groups to whom the policy is
        not applied."

    desc 'fix',
       "From Azure Portal
        1. From Azure Home open Portal menu in the top left, and select Microsoft Entra
        ID.
        2. Select Security.
        3. Select Conditional Access.
        4. Click + New policy.
        5. Enter a name for the policy.
        6. Select Users or workload identities.
        Page 45
        7. Under Include, select All users.
        8. Under Exclude, check Users and groups.
        9. Select users this policy should not apply to and click Select.
        10. Select Cloud apps or actions.
        11. Select All cloud apps.
        12. Select Grant.
        13. Under Grant access, check Require multifactor authentication and click
        Select.
        14. Set Enable policy to Report-only.
        15. Click Create.
        After testing the policy in report-only mode, update the Enable policy setting from
        Report-only to On."

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/troubleshoot-conditional-access-what-if'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-insights-reporting'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-7-restrict-resource-access-based-on--conditions'

    describe 'benchmark' do
        skip 'configure'
    end
end