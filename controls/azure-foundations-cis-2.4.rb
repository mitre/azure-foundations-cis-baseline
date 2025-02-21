control 'azure-foundations-cis-2.4' do
  title 'Ensure Guest Users Are Reviewed on a Regular Basis'
  desc "Microsoft Entra ID has native and extended identity functionality allowing you to invite
        people from outside your organization to be guest users in your cloud account and sign
        in with their own work, school, or social identities."

  desc 'rationale',
       "Guest users are typically added outside your employee on-boarding/off-boarding
        process and could potentially be overlooked indefinitely. To prevent this, guest users
        should be reviewed on a regular basis. During this audit, guest users should also be
        determined to not have administrative privileges."

  desc 'impact',
       "Before removing guest users, determine their use and scope. Like removing any user,
        there may be unforeseen consequences to systems if an account is removed without
        careful consideration."

  desc 'check',
       "Audit from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Users
        4. Click on Add filter
        5. Select User type
        6. Select Guest from the Value dropdown
        7. Click Apply
        8. Audit the listed guest users
        Audit from Azure CLI
        az ad user list --query '[?userType=='Guest']'
        Ensure all users listed are still required and not inactive.
        Audit from Azure PowerShell
        Get-AzureADUser |Where-Object {$_.UserType -like 'Guest'} |Select-Object
        DisplayName, UserPrincipalName, UserType -Unique
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: e9ac8f8e-ce22-4355-8f04-99b911d6be52 - Name: 'Guest accounts
        with read permissions on Azure resources should be removed'
        • Policy ID: 94e1c2ac-cbbe-4cac-a2b5-389c812dee87 - Name: 'Guest accounts
        with write permissions on Azure resources should be removed'
        • Policy ID: 339353f6-2387-4a45-abe4-7f529d121046 - Name: 'Guest accounts
        with owner permissions on Azure resources should be removed"

  desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Users
        4. Click on Add filter
        5. Select User type
        6. Select Guest from the Value dropdown
        7. Click Apply
        8. Check the box next to all Guest users that are no longer required or are inactive
        9. Click Delete
        10. Click OK
        Remediate from Azure CLI
        Before deleting the user, set it to inactive using the ID from the Audit Procedure to
        determine if there are any dependent systems.
        az ad user update --id <exampleaccountid@domain.com> --account-enabled
        {false}
        After determining that there are no dependent systems delete the user.
        Remove-AzureADUser -ObjectId <exampleaccountid@domain.com>
        Remediate from Azure PowerShell
        Before deleting the user, set it to inactive using the ID from the Audit Procedure to
        determine if there are any dependent systems.
        Set-AzureADUser -ObjectId '<exampleaccountid@domain.com>' -AccountEnabled
        false
        After determining that there are no dependent systems delete the user.
        PS C:\>Remove-AzureADUser -ObjectId exampleaccountid@domain.com"

  impact 0.5
  tag nist: ['AC-2', 'AC-2(3)', 'AC-1', 'AC-2(1)', 'AC-5', 'AC-6', 'AC-6(1)', 'AC-6(7)', 'AU-9(4)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['5.1', '5.3', '6.2', '6.8'] }]

  ref 'https://docs.microsoft.com/en-us/azure/active-directory/b2b/user-properties'
  ref 'https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/add-users-azure-active-directory#delete-a-user'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-4-review-and-reconcile-user-access-regularly'
  ref 'https://www.microsoft.com/en-us/security/business/identity-access-management/azure-ad-pricing'
  ref 'https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-manage-inactive-user-accounts'
  ref 'https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-users-restore'

  describe 'benchmark' do
    skip 'The check for this control needs to be done manually'
  end
end
