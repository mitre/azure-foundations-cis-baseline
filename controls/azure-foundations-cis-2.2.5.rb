control 'azure-foundations-cis-2.2.5' do
  title 'Ensure that A Multi-factor Authentication Policy Exists for All Users'
  desc 'For designated users, they will be prompted to use their multi-factor authentication (MFA) process on logins.'

  desc 'rationale',
       'Enabling multi-factor authentication is a recommended setting to limit the potential of accounts being compromised and limiting access to authenticated personnel.'

  desc 'impact',
       "There is an increased cost, as Conditional Access policies require Microsoft Entra ID P1
        or P2. Similarly, this may require additional overhead to maintain if users lose access to
        their MFA.
        NOTE: Starting July 2024, Microsoft will begin requiring MFA for All Users - including
        Break Glass Accounts. By the end of October 2024, this requirement will be enforced.
        Physical FIDO2 security keys, or a certificate kept on secure removable storage can
        fulfill this MFA requirement. If opting for a physical device, that device should be kept in
        a very secure, documented physical location."

  desc 'check',
       "Audit from Azure Portal
        1. From Azure Home open the Portal Menu in the top left, and select Microsoft
        Entra ID.
        2. Scroll down in the menu on the left, and select Security.
        3. Select on the left side Conditional Access.
        4. Select Policies.
        5. Select the policy you wish to audit.
        6. Click the blue text under Users.
        7. View under Include the corresponding users and groups to whom the policy is
        applied.
        8. View under Exclude to determine which users and groups to whom the policy is
        not applied."

  desc 'fix',
       "1. From Azure Home open Portal menu in the top left, and select Microsoft Entra ID.
        2. Select Security.
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
        13. Click the blue text under Grant.
        14. Under Grant access, check Require multifactor authentication and click
        Select.
        15. Set Enable policy to Report-only.
        16. Click Create.
        After testing the policy in report-only mode, update the Enable policy setting from
        Report-only to On."

  impact 0.5
  tag nist: ['IA-2(1)', 'IA-2(2)', 'AC-19', 'AC-2(1)', 'AC-3']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['6.3', '6.4', '6.7'] }]

  ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa'
  ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/troubleshoot-conditional-access-what-if'
  ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-insights-reporting'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-7-restrict-resource-access-based-on--conditions'

  describe 'Ensure that A Multi-factor Authentication Policy Exists for All Users' do
    skip 'The check for this control needs to be done manually'
  end
end
