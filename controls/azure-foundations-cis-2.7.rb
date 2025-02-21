control 'azure-foundations-cis-2.7' do
  title "Ensure that account 'Lockout duration in seconds' is greater than or equal to '60'"
  desc "The account lockout duration value determines how long an account retains the status
        of lockout, and therefore how long before a user can continue to attempt to login after
        passing the lockout threshold."

  desc 'rationale',
       "Account lockout is a method of protecting against brute-force and password spray
        attacks. Once the lockout threshold has been exceeded, the account enters a locked-
        out state which prevents all login attempts for a variable duration. The lockout in
        combination with a reasonable duration reduces the total number of failed login
        attempts that a malicious actor can execute in a given period of time."

  desc 'impact',
       "If account lockout duration is set too low (less than 60 seconds), malicious actors can
        perform more password spray and brute-force attempts over a given period of time.
        If the account lockout duration is set too high (more than 300 seconds) users may
        experience inconvenient delays during lockout."

  desc 'check',
       "Audit from Azure Portal
        1. From Azure Home select the Portal Menu.
        2. Select Microsoft Entra ID.
        3. Under Manage, select Security.
        4. Under Manage, select Authentication methods.
        5. Under Manage, select Password protection.
        6. Ensure that Lockout duration in seconds is set to 60 or higher."

  desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu.
        2. Select Microsoft Entra ID.
        3. Under Manage, select Security.
        4. Under Manage, select Authentication methods.
        5. Under Manage, select Password protection.
        6. Set the Lockout duration in seconds to 60 or higher.
        7. Click Save."

  impact 0.5
  tag nist: ['AC-7', 'AC-19']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['4.10'] }]

  ref 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout#manage-microsoft-entra-smart-lockout-values'

  describe "Ensure that account 'Lockout Threshold' is less than or equal to '10'" do
    skip 'The check for this control needs to be done manually'
  end
end
