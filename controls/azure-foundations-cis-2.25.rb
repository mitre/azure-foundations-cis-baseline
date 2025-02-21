control 'azure-foundations-cis-2.25' do
  title "Ensure That `Subscription leaving Microsoft Entra ID directory` and `Subscription entering Microsoft Entra ID directory` Is Set To 'Permit No One'"
  desc "Users who are set as subscription owners are able to make administrative changes to
        the subscriptions and move them into and out of Microsoft Entra ID."

  desc 'rationale',
       "Permissions to move subscriptions in and out of Microsoft Entra ID directory must only
        be given to appropriate administrative personnel. A subscription that is moved into an
        Microsoft Entra ID directory may be within a folder to which other users have elevated
        permissions. This prevents loss of data or unapproved changes of the objects within by
        potential bad actors."

  desc 'impact',
       'Subscriptions will need to have these settings turned off to be moved.'

  desc 'check',
       "From Azure Portal
        1. From the Azure Portal Home select the portal menu
        2. Select Subscriptions
        3. In the Advanced options drop-down menu, select Manage Policies
        4. Ensure Subscription leaving Microsoft Entra ID directory and
        Subscription entering Microsoft Entra ID directory are set to Permit no
        one"

  desc 'fix',
       "Remediate from Azure Portal
        1. From the Azure Portal Home select the portal menu
        2. Select Subscriptions
        3. In the Advanced options drop-down menu, select Manage Policies
        4. Set Subscription leaving Microsoft Entra tenant and Subscription
        entering Microsoft Entra tenant to Permit no one
        5. Click Save changes"

  impact 0.5
  tag nist: ['AC-6(2)', 'AC-6(5)', 'IA-4', 'IA-5', 'AC-1', 'AC-2', 'AC-2(1)', 'AC-1', 'AC-2', 'AC-2(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['5.4', '6.1', '6.2'] }]

  ref 'https://docs.microsoft.com/en-us/azure/cost-management-billing/manage/manage-azure-subscription-policy'
  ref 'https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-how-subscriptions-associated-directory'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-2-protect-identity-and-authentication-systems'

  describe "Ensure That `Subscription leaving Microsoft Entra ID directory` and `Subscription entering Microsoft Entra ID directory` Is Set To 'Permit No One'" do
    skip 'The check for this control needs to be done manually'
  end
end
