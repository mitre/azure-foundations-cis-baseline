control 'azure-foundations-cis-2.2.8' do
  title 'Ensure Multifactor Authentication is Required to access Microsoft Admin Portals'
  desc "This recommendation ensures that users accessing Microsoft Admin Portals (i.e.
        Microsoft 365 Admin, Microsoft 365 Defender, Exchange Admin Center, Azure Portal,
        etc.) are required to use multifactor authentication (MFA) credentials when logging into
        an Admin Portal."

  desc 'rationale',
       "Administrative Portals for Microsoft Azure should be secured with a higher level of
        scrutiny to authenticating mechanisms. Enabling multifactor authentication is
        recommended to reduce the potential for abuse of Administrative actions, and to
        prevent intruders or compromised admin credentials from changing administrative
        settings.
        IMPORTANT: While this recommendation allows exceptions to specific Users or
        Groups, they should be very carefully tracked and reviewed for necessity on a regular
        interval through an Access Review process. It is important that this rule be built to
        include 'All Users' to ensure that all users not specifically excepted will be required to
        use MFA to access Admin Portals."

  desc 'impact',
       "Conditional Access policies require Microsoft Entra ID P1 or P2 licenses. Similarly, they
        may require additional overhead to maintain if users lose access to their MFA. Any
        users or groups which are granted an exception to this policy should be carefully
        tracked, be granted only minimal necessary privileges, and conditional access
        exceptions should be reviewed or investigated."

  desc 'check',
       "Audit from Azure Portal
        1. From the Azure Admin Portal dashboard, open Microsoft Entra ID.
        2. In the menu on the left of the Entra ID blade, click Security.
        3. In the menu on the left of the Security blade, click Conditional Access.
        4. In the menu on the left of the Conditional Access blade, click Policies.
        5. Click on the name of the policy you wish to audit.
        6. Click the blue text under Users.
        7. Under the Include section of Users, review Users and Groups to ensure that
        All Users is selected.
        8. Under the Exclude section of Users, review the Users and Groups that are
        excluded from the policy (NOTE: this should be limited to break-glass emergency
        access accounts, non-interactive service accounts, and other carefully
        considered exceptions).
        9. On the left side, click the blue text under Target Resources.
        10. Under the Include section of Target resources, ensure the Select apps radio
        button is selected.
        11. Under Select, ensure Microsoft Admin Portals is listed."

  desc 'fix',
       "From Azure Portal
        1. From the Azure Admin Portal dashboard, open Microsoft Entra ID.
        2. Click Security in the Entra ID blade.
        3. Click Conditional Access in the Security blade.
        4. Click Policies in the Conditional Access blade.
        5. Click + New policy.
        6. Enter a name for the policy.
        7. Click the blue text under Users.
        8. Under Include, select All users.
        9. Under Exclude, check Users and groups.
        10. Select users or groups to be exempted from this policy (e.g. break-glass
        emergency accounts, and non-interactive service accounts) then click the Select
        button.
        11. Click the blue text under Target Resources.
        12. Under Include, click the Select apps radio button.
        13. Click the blue text under Select.
        14. Check the box next to Microsoft Admin Portals then click the Select button.
        15. Click the blue text under Grant.
        16. Under Grant access check the box for Require multifactor authentication
        then click the Select button.
        17. Before creating, set Enable policy to Report-only.
        18. Click Create.
        After testing the policy in report-only mode, update the Enable policy setting from
        Report-only to On."

  impact 0.5
  tag nist: ['IA-2(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['6.5'] }]

  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-7-restrict-resource-access-based-on--conditions'
  ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-users-groups'
  ref 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-mfa-admin-portals'

  describe 'Ensure Multifactor Authentication is Required to access Microsoft Admin Portals' do
    skip 'The check for this control needs to be done manually'
  end
end
