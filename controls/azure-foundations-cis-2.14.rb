control 'azure-foundations-cis-2.14' do
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
       "Audit from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Users
        4. Under Manage, select User settings
        5. Ensure that Users can register applications is set to No
        Audit from PowerShell
        (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Format-List
        AllowedToCreateApps
        Command should return the value of False"

    desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Users
        4. Under Manage, select User settings
        5. Set Users can register applications to No
        6. Click Save
        Remediate from PowerShell
        $param = @{ AllowedToCreateApps = '$false' }
        Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions $param"

    impact 0.5
    tag nist: ['CM-7(2)','CM-8(3)','CM-10','CM-11','CM-8(3)','AC-2(1)','AC-3']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['2.3','2.4','6.7'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/roles/delegate-app-roles#restrict-who-can-create-applications'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-how-applications-are-added#who-has-permission-to-add-applications-to-my-azure-ad-instance'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'
    ref 'https://blogs.msdn.microsoft.com/exchangedev/2014/06/05/managing-user-consent-for-applications-using-office-365-apis/'
    ref 'https://nicksnettravels.builttoroam.com/post/2017/01/24/Admin-Consent-for-Permissions-in-Azure-Active-Directory.aspx'
    ref 'https://docs.microsoft.com/en-us/powershell/module/msonline/get-msolcompanyinformation?view=azureadps-1.0'
    ref 'https://docs.microsoft.com/en-us/powershell/module/msonline/set-msolcompanysettings?view=azureadps-1.0'
    
    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end