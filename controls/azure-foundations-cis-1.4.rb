control 'azure-foundations-cis-1.1.1' do
    title 'Ensure Guest Users Are Reviewed on a Regular Basis'
    desc "Microsoft Entra ID is extended to include Azure AD B2B collaboration, allowing you to
        invite people from outside your organization to be guest users in your cloud account and
        sign in with their own work, school, or social identities. Guest users allow you to share
        your company's applications and services with users from any other organization, while
        maintaining control over your own corporate data.
        Work with external partners, large or small, even if they don't have Azure AD or an IT
        department. A simple invitation and redemption process lets partners use their own
        credentials to access your company's resources as a guest user.
        Guest users in every subscription should be review on a regular basis to ensure that
        inactive and unneeded accounts are removed."

    desc 'rationale',
        "Guest users in the Microsoft Entra ID are generally required for collaboration purposes
        in Office 365, and may also be required for Azure functions in enterprises with multiple
        Azure tenants. Guest users are typically added outside your employee on-boarding/off-
        boarding process and could potentially be overlooked indefinitely, leading to a potential
        vulnerability. To prevent this, guest users should be reviewed on a regular basis. During
        this audit, guest users should also be determined to not have administrative privileges."

    desc 'impact',
        "Before removing guest users, determine their use and scope. Like removing any user,
        there may be unforeseen consequences to systems if it is deleted."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Users
        4. Click on Add filter
        5. Select User type
        6. Select Guest from the Value dropdown
        7. Click Apply
        8. Audit the listed guest users
        Page 59
        From Azure CLI
        az ad user list --query '[?userType=='Guest']'
        Ensure all users listed are still required and not inactive.
        From Azure PowerShell
        Get-AzureADUser |Where-Object {$_.UserType -like 'Guest'} |Select-Object
        DisplayName, UserPrincipalName, UserType -Unique
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: e9ac8f8e-ce22-4355-8f04-99b911d6be52 - Name: 'Guest accounts
        with read permissions on Azure resources should be removed'
        • Policy ID: 94e1c2ac-cbbe-4cac-a2b5-389c812dee87 - Name: 'Guest accounts
        with write permissions on Azure resources should be removed'
        • Policy ID: 339353f6-2387-4a45-abe4-7f529d121046 - Name: 'Guest accounts
        with owner permissions on Azure resources should be removed'"

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Users
        4. Click on Add filter
        5. Select User type
        6. Select Guest from the Value dropdown
        7. Click Apply
        8. Delete all Guest users that are no longer required or are inactive
        From Azure CLI
        Before deleting the user, set it to inactive using the ID from the Audit Procedure to
        determine if there are any dependent systems.
        az ad user update --id <exampleaccountid@domain.com> --account-enabled
        {false}
        After determining that there are no dependent systems delete the user.
        Remove-AzureADUser -ObjectId <exampleaccountid@domain.com>
        Page 60
        From Azure PowerShell
        Before deleting the user, set it to inactive using the ID from the Audit Procedure to
        determine if there are any dependent systems.
        Set-AzureADUser -ObjectId '<exampleaccountid@domain.com>' -AccountEnabled
        false
        After determining that there are no dependent systems delete the user.
        PS C:\>Remove-AzureADUser -ObjectId <exampleaccountid@domain.com>"

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/b2b/user-properties'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/add-users-azure-active-directory#delete-a-user'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-4-review-and-reconcile-user-access-regularly'
    ref 'https://www.microsoft.com/en-us/security/business/identity-access-management/azure-ad-pricing'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-manage-inactive-user-accounts'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-users-restore'

    describe 'benchmark' do
        skip 'configure'
    end
end