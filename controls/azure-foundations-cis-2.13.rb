control 'azure-foundations-cis-2.13' do
  title "Ensure 'User consent for applications' Is Set To 'Allow for Verified Publishers'"
  desc "Allow users to provide consent for selected permissions when a request is coming from
        a verified publisher."

  desc 'rationale',
       "If Microsoft Entra ID is running as an identity provider for third-party applications,
        permissions and consent should be limited to administrators or pre-approved. Malicious
        applications may attempt to exfiltrate data or abuse privileged user accounts."

  desc 'impact',
       'Enforcing this setting may create additional requests that administrators need to review.'

  desc 'check',
       "Audit from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Enterprise applications
        4. Under Security, select Consent and permissions`
        5. Under Manage, select User consent settings
        6. Under User consent for applications, ensure Allow user consent for
        apps from verified publishers, for selected permissions is selected
        Audit from PowerShell
        Connect-MgGraph
        (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object
        -ExpandProperty PermissionGrantPoliciesAssigned
        The command should return either ManagePermissionGrantsForSelf.microsoft-
        user-default-low or a custom app consent policy id if one is in use."

  desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Enterprise applications
        4. Under Security, select Consent and permissions`
        5. Under Manage, select User consent settings
        6. Under User consent for applications, select Allow user consent for
        apps from verified publishers, for selected permissions
        7. Click Save"

  impact 0.5
  tag nist: ['CM-7(2)', 'CM-8(3)', 'CM-10', 'CM-11', 'CM-7(5)', 'CM-10', 'IA-4', 'IA-5', 'AC-1', 'AC-2', 'AC-2(1)', 'AC-2(1)', 'AC-3']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['2.3', '2.5', '6.1', '6.7'] }]

  ref 'https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent#configure-user-consent-to-applications'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
  ref 'https://docs.microsoft.com/en-us/powershell/module/msonline/set-msolcompanysettings?view=azureadps-1.0'
  ref 'https://docs.microsoft.com/en-us/powershell/module/msonline/get-msolcompanyinformation?view=azureadps-1.0'

  client_secret = input('client_secret')
  client_id = input('client_id')
  tenant_id = input('tenant_id')
  custom_policy_id = input('custom_policy_id')
  custom_policy_id_list = custom_policy_id.map { |policy_id| "'#{policy_id}'" }.join(', ')
  ensure_consent_apps_allow_verified_publishers_script = %(
     $ErrorActionPreference = "Stop"
     $password = ConvertTo-SecureString -String '#{client_secret}' -AsPlainText -Force
     $ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential('#{client_id}',$password)
     Connect-MgGraph -TenantId '#{tenant_id}' -ClientSecretCredential $ClientSecretCredential -NoWelcome
     $custom_policy_id = @(#{custom_policy_id_list})
     $acceptable_value = 'ManagePermissionGrantsForSelf.microsoft-user-default-low'
     $containsKnownValue = $permissions -contains $acceptable_value
     $permissions = (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object -ExpandProperty PermissionGrantPoliciesAssigned
     $permissionsJoined = $permissions -join ", "
     $containsCustomPolicyId = $custom_policy_id | ForEach-Object { $permissions -contains $_ } | Where-Object { $_ } | Select-Object -First 1
     $containsCustomPolicyId = $containsCustomPolicyId -ne $null

      if ($containsCustomPolicyId -or $containsKnownValue) {
      }
      else {
            Write-Host "The following incorrect policies are present: $permissionsJoined"
      }
   )

  pwsh_output = powershell(ensure_consent_apps_allow_verified_publishers_script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe 'Ensure the output from DefaultUserRolePermissions.PermissionGrantPoliciesAssigned setting' do
    subject { pwsh_output.stdout.strip }
    it 'is set to either ManagePermissionGrantsForSelf.microsoft-user-default-low or custom policy id' do
      failure_message = "Error:#{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
