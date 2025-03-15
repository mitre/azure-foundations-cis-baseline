control 'azure-foundations-cis-2.3' do
  title "Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'"
  desc 'Require administrators or appropriately delegated users to create new tenants.'

  desc 'rationale',
       "It is recommended to only allow an administrator to create new tenants. This prevent
        users from creating new Microsoft Entra ID or Azure AD B2C tenants and ensures that
        only authorized users are able to do so."

  desc 'impact',
       'Enforcing this setting will ensure that only authorized users are able to create new tenants.'

  desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Users
        4. Select User settings
        5. Ensure that Restrict non-admin users from creating tenants is set to Yes
        From PowerShell
        Import-Module Microsoft.Graph.Identity.SignIns
        Connect-MgGraph -Scopes 'Policy.ReadWrite.Authorization'
        Get-MgPolicyAuthorizationPolicy | Select-Object -ExpandProperty
        DefaultUserRolePermissions | Format-List
        Review the 'DefaultUserRolePermissions' section of the output. Ensure that
        AllowedToCreateTenants is not 'True'."

  desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Users
        4. Under Manage, select User settings
        5. Set Restrict non-admin users from creating tenants to Yes
        6. Click Save
        Remediate from PowerShell
        Import-Module Microsoft.Graph.Identity.SignIns
        Connect-MgGraph -Scopes 'Policy.ReadWrite.Authorization'
        Select-MgProfile -Name beta
        $params = @{
        DefaultUserRolePermissions = @{
        AllowedToCreateTenants = $false
        }
        }
        Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId -BodyParameter
        $params"

  impact 0.5
  tag nist: ['AC-2', 'AC-5', 'AC-6', 'AC-6(1)', 'AC-6(7)', 'AU-9(4)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['6.8'] }]

  ref 'https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions'
  ref 'https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#tenant-creator'
  ref 'https://blog.admindroid.com/disable-users-creating-new-azure-ad-tenants-in-microsoft-365/'

  client_secret = input('client_secret')
  client_id = input('client_id')
  tenant_id = input('tenant_id')
  ensure_restricted_non_admins_not_create_tenants_script = %(
     $ErrorActionPreference = "Stop"
     $password = ConvertTo-SecureString -String '#{client_secret}' -AsPlainText -Force
     $ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential('#{client_id}',$password)
     Connect-MgGraph -TenantId '#{tenant_id}' -ClientSecretCredential $ClientSecretCredential -NoWelcome
   	Write-Output (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.AllowedToCreateTenants
   )

  pwsh_output = powershell(ensure_restricted_non_admins_not_create_tenants_script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe 'Ensure that DefaultUserRolePermissions.AllowedToCreateTenants setting' do
    subject { pwsh_output.stdout.strip }
    it 'is not set to True' do
      expect(subject).not_to eq('True')
    end
  end
end
