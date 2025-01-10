control 'azure-foundations-cis-1.1.1' do
    title "Ensure That 'Notify all admins when other admins reset their password?' is set to 'Yes'"
    desc "Ensure that all Global Administrators are notified if any other administrator resets their password."

    desc 'rationale',
        "Global Administrator accounts are sensitive. Any password reset activity notification,
        when sent to all Global Administrators, ensures that all Global administrators can
        passively confirm if such a reset is a common pattern within their group. For example, if
        all Global Administrators change their password every 30 days, any password reset
        activity before that may require administrator(s) to evaluate any unusual activity and
        confirm its origin."

    desc 'impact',
        "All Global Administrators will receive a notification from Azure every time a password is
        reset. This is useful for auditing procedures to confirm that there are no out of the
        ordinary password resets for Global Administrators. There is additional overhead,
        however, in the time required for Global Administrators to audit the notifications. This
        setting is only useful if all Global Administrators pay attention to the notifications, and
        audit each one."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Users
        4. Select Password reset
        5. Under Manage, select Notifications
        6. Ensure that notify all admins when other admins reset their password? is
        set to Yes"

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        Page 72
        3. Select Users
        4. Select Password reset
        5. Under Manage, select Notifications
        6. Set Notify all admins when other admins reset their password? to Yes"

    impact 0.5
    tag nist: ['check NIST SP 800-53, Revision 5']
    tag severity: 'low, medium, or high '
    tag cis_controls: [{ '8.1' => ['check cis controls navigator'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-passwords-how-it-works#notifications'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-sspr-deployment'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-sspr#set-up-notifications-and-customizations'

    describe 'benchmark' do
        skip 'configure'
    end
end