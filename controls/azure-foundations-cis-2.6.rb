control 'azure-foundations-cis-2.6' do
    title "Ensure that account 'Lockout Threshold' is less than or equal to '10'"
    desc "The account lockout threshold determines how many failed login attempts are permitted
        prior to placing the account in a locked-out state and initiating a variable lockout
        duration."

    desc 'rationale',
        "Account lockout is a method of protecting against brute-force and password spray
        attacks. Once the lockout threshold has been exceeded, the account enters a locked-
        out state which prevents all login attempts for a variable duration. The lockout in
        combination with a reasonable duration reduces the total number of failed login
        attempts that a malicious actor can execute in a given period of time."

    desc 'impact',
        "If account lockout threshold is set too low (less than 3), users may experience frequent
        lockout events and the resulting security alerts may contribute to alert fatigue.
        If account lockout threshold is set too high (more than 10), malicious actors can
        programmatically execute more password attempts in a given period of time."

    desc 'check',
       "Audit from Azure Portal
        1. From Azure Home select the Portal Menu.
        2. Select Microsoft Entra ID.
        3. Under Manage, select Security.
        4. Under Manage, select Authentication methods.
        5. Under Manage, select Password protection.
        6. Ensure that Lockout threshold is set to 10 or fewer"

    desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu.
        2. Select Microsoft Entra ID.
        3. Under Manage, select Security.
        4. Under Manage, select Authentication methods.
        5. Under Manage, select Password protection.
        6. Set the Lockout threshold to 10 or fewer.
        7. Click Save."

    impact 0.5
    tag nist: ['AC-7','AC-19']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['4.10'] }]

    ref 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout#manage-microsoft-entra-smart-lockout-values'

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end