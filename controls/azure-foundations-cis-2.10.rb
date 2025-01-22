control 'azure-foundations-cis-2.10' do
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
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Users
        4. Under Manage, select Password reset
        5. Under Manage, select Notifications
        6. Set Notify users on password resets? to Yes
        7. Click Save"

    impact 0.5
    tag nist: ['AC-2(1)','AC-3']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['6.7'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-sspr#set-up-notifications-and-customizations'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-passwords-how-it-works#notifications'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-sspr-deployment'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'

    describe 'benchmark' do
        skip 'configure'
    end
end