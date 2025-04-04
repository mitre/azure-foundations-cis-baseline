control 'azure-foundations-cis-2.9' do
  title "Ensure that 'Number of days before users are asked to re-confirm their authentication information' is not set to '0'"
  desc "Ensure that the number of days before users are asked to re-confirm their
        authentication information is not set to 0."

  desc 'rationale',
       "This setting is necessary if you have setup 'Require users to register when signing in
        option'. If authentication re-confirmation is disabled, registered users will never be
        prompted to re-confirm their existing authentication information. If the authentication
        information for a user changes, such as a phone number or email, then the password
        reset information for that user reverts to the previously registered authentication
        information."

  desc 'impact',
       'Users will be prompted for their multifactor authentication at the duration set here.'

  desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Then Users
        4. Select Password reset
        5. Then Registration
        6. Ensure that Number of days before users are asked to re-confirm their
        authentication information is not set to 0"

  desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Users
        4. Under Manage, select Password reset
        5. Under Manage, select Registration`
        6. Set the Number of days before users are asked to re-confirm their
        authentication information to your organization-defined frequency
        7. Click Save"

  impact 0.5
  tag nist: ['AC-1', 'AC-2', 'AC-2(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['6.2'] }]

  ref 'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-passwords-how-it-works#registration'
  ref 'https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-sspr-deployment'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
  ref 'https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-methods'

  describe "Ensure that 'Number of days before users are asked to re-confirm their authentication information' is not set to '0'" do
    skip 'The check for this control needs to be done manually'
  end
end
