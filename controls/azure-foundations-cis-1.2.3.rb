control 'azure-foundations-cis-1.1.1' do
    title 'Ensure that A Multi-factor Authentication Policy Exists for Administrative Groups'
    desc "For designated users, they will be prompted to use their multi-factor authentication (MFA) process on login"

    desc 'rationale',
        "Enabling multi-factor authentication is a recommended setting to limit the use of Administrative accounts to authenticated personnel."

    desc 'impact',
        "There is an increased cost, as Conditional Access policies require Microsoft Entra ID
        P1. Similarly, MFA may require additional overhead to maintain. There is also a
        potential scenario in which the multi-factor authentication method can be lost, and
        administrative users are no longer able to log in. For this scenario, there should be an
        emergency access account. Please see References for creating this."
    
    desc 'check',
       "From Azure Portal
        1. From Azure Home open the Portal Menu in the top left, and select Microsoft
        Entra ID.
        2. Select Security.
        3. Select Conditional Access.
        4. Select the policy you wish to audit.
        5. View under Users and Groups the corresponding users and groups to whom the
        policy is applied. Be certain the emergency access account is not in the list.
        6. View under Exclude to determine which Users and groups to whom the policy is
        not applied."

    desc 'fix',
       "From Azure Portal
        1. From Azure Home open the Portal Menu in top left, and select Microsoft Entra
        ID.
        2. Select Security.
        3. Select Conditional Access.
        4. Click + New policy.
        Page 42
        5. Enter a name for the policy.
        6. Select Users or workload identities.
        7. Check Users and groups.
        8. Select administrative groups this policy should apply to and click Select.
        9. Under Exclude, check Users and groups.
        10. Select users this policy not should apply to and click Select.
        11. Select Cloud apps or actions.
        12. Select All cloud apps.
        13. Select Grant.
        14. Under Grant access, check Require multifactor authentication and click
        Select.
        15. Set Enable policy to Report-only.
        16. Click Create.
        After testing the policy in report-only mode, update the Enable policy setting from
        Report-only to On"

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-admin-mfa'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/troubleshoot-conditional-access-what-if'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-insights-reporting'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/plan-conditional-access'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-7-restrict-resource-access-based-on--conditions'

    describe 'benchmark' do
        skip 'configure'
    end
end