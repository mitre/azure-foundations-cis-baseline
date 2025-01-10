control 'azure-foundations-cis-1.1.1' do
    title "Ensure that 'Notify users on password resets?' is set to 'Yes'"
    desc "Ensure that users are notified on their primary and secondary emails on password resets."

    desc 'rationale',
        "User notification on password reset is a proactive way of confirming password reset
        activity. It helps the user to recognize unauthorized password reset activities."

    desc 'impact',
        "Users will receive emails alerting them to password changes to both their primary and
        secondary emails."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Users
        4. Go to Password reset
        5. Under Manage, select Notifications
        6. Ensure that Notify users on password resets? is set to Yes"

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Users
        4. Select Password reset
        5. Under Manage, select Notifications
        6. Set Notify users on password resets? to Yes"

    impact 0.5
    tag nist: ['check NIST SP 800-53, Revision 5']
    tag severity: 'low, medium, or high '
    tag cis_controls: [{ '8.1' => ['check cis controls navigator'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-sspr#set-up-notifications-and-customizations'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-passwords-how-it-works#notifications'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-sspr-deployment'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'

    describe 'benchmark' do
        skip 'configure'
    end
end