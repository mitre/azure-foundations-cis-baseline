control 'azure-foundations-cis-2.2.4
' do
    title 'Ensure that A Multi-factor Authentication Policy Exists for Administrative Groups'
    desc "For designated users, they will be prompted to use their multi-factor authentication (MFA) process on login"

    desc 'rationale',
        "Enabling multi-factor authentication is a recommended setting to limit the use of Administrative accounts to authenticated personnel."

    desc 'impact',
        "There is an increased cost, as Conditional Access policies require Microsoft Entra ID
        P1. Similarly, MFA may require additional overhead to maintain. There is also a
        potential scenario in which the multi-factor authentication method can be lost, and
        administrative users are no longer able to log in. For this scenario, there should be an
        emergency access account. Please see References for creating this.
        NOTE: Starting July 2024, Microsoft will begin requiring MFA for All Users - including
        Break Glass Accounts. By the end of October 2024, this requirement will be enforced.
        Physical FIDO2 security keys, or a certificate kept on secure removable storage can
        fulfill this MFA requirement. If opting for a physical device, that device should be kept in
        a very secure, documented physical location."
    
    desc 'check',
       "Audit from Azure Portal
        1. From Azure Home open the Portal Menu in the top left, and select Microsoft
        Entra ID.
        2. Select Security.
        3. Select Conditional Access.
        4. Select Policies.
        5. Select the policy you wish to audit.
        6. Click the blue text under Users.
        7. View under Include the corresponding users and groups to whom the policy is
        applied. Be certain the emergency access account is not in the list.
        8. View under Exclude to determine which Users and groups to whom the policy is
        not applied."

    desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home open the Portal Menu in top left, and select Microsoft Entra
        ID.
        2. Select Security.
        3. Select Conditional Access.
        4. Select Policies.
        5. Click + New policy.
        6. Enter a name for the policy.
        7. Click the blue text under Users.
        8. Select Select users and groups.
        9. Select administrative groups this policy should apply to and click Select.
        10. Under Exclude, check Users and groups.
        11. Select users this policy not should apply to and click Select.
        12. Click the blue text under Target resources.
        13. Select All cloud apps.
        14. Click the blue text under Grant.
        15. Under Grant access, check Require multifactor authentication and click
        Select.
        16. Set Enable policy to Report-only.
        17. Click Create.
        After testing the policy in report-only mode, update the Enable policy setting from
        Report-only to On."

    impact 0.5
    tag nist: ['IA-2(1)','IA-2(2)','AC-19','IA-2(1)','AC-2(1)','AC-3']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['6.3','6.4','6.5','6.7'] }]

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