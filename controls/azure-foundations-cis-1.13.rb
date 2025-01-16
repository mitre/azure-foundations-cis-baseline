control 'azure-foundations-cis-1.13' do
    title "Ensure That 'Users Can Register Applications' Is Set to 'No'"
    desc "Require administrators or appropriately delegated users to register third-party applications."

    desc 'rationale',
        "It is recommended to only allow an administrator to register custom-developed
        applications. This ensures that the application undergoes a formal security review and
        approval process prior to exposing Microsoft Entra ID data. Certain users like
        developers or other high-request users may also be delegated permissions to prevent
        them from waiting on an administrative user. Your organization should review your
        policies and decide your needs."

    desc 'impact',
        "Enforcing this setting will create additional requests for approval that will need to be
        addressed by an administrator. If permissions are delegated, a user may approve a
        malevolent third party application, potentially giving it access to your data."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Users
        4. Select User settings
        5. Ensure that Users can register applications is set to No
        From PowerShell
        Connect-MsolService
        Get-MsolCompanyInformation | Select-Object
        UsersPermissionToCreateLOBAppsEnabled
        Command should return UsersPermissionToCreateLOBAppsEnabled with the value of
        False"

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Users
        4. Select User settings
        5. Set Users can register applications to No
        From PowerShell
        Connect-MsolService
        Set-MsolCompanyInformation -UsersPermissionToCreateLOBAppsEnabled $False"

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/roles/delegate-app-roles#restrict-who-can-create-applications'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-how-applications-are-added#who-has-permission-to-add-applications-to-my-azure-ad-instance'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'
    ref 'https://blogs.msdn.microsoft.com/exchangedev/2014/06/05/managing-user-consent-for-applications-using-office-365-apis/'
    ref 'https://nicksnettravels.builttoroam.com/post/2017/01/24/Admin-Consent-for-Permissions-in-Azure-Active-Directory.aspx'
    ref 'https://docs.microsoft.com/en-us/powershell/module/msonline/get-msolcompanyinformation?view=azureadps-1.0'
    ref 'https://docs.microsoft.com/en-us/powershell/module/msonline/set-msolcompanysettings?view=azureadps-1.0'
    
    describe 'benchmark' do
        skip 'configure'
    end
end