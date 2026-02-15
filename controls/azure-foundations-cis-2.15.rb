control 'azure-foundations-cis-2.15' do
  title "Ensure That 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects' "
  desc 'Limit guest user permissions.'

  desc 'rationale',
       "Limiting guest access ensures that guest accounts do not have permission for certain
        directory tasks, such as enumerating users, groups or other directory resources, and
        cannot be assigned to administrative roles in your directory. Guest access has three
        levels of restriction.
        1. Guest users have the same access as members (most inclusive),
        2. Guest users have limited access to properties and memberships of directory
        objects (default value),
        3. Guest user access is restricted to properties and memberships of their own
        directory objects (most restrictive).
        The recommended option is the 3rd, most restrictive: 'Guest user access is restricted to
        their own directory object'."

  desc 'impact',
       "This may create additional requests for permissions to access resources that
        administrators will need to approve.
        According to https://learn.microsoft.com/en-us/azure/active-directory/enterprise-
        users/users-restrict-guest-permissions#services-currently-not-supported
        Service without current support might have compatibility issues with the new guest
        restriction setting.
        • Forms
        • Project
        • Yammer
        • Planner in SharePoint"

  desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Then External Identities
        4. Select External collaboration settings
        5. Under Guest user access, ensure that Guest user access restrictions is set
        to Guest user access is restricted to properties and memberships of
        their own directory objects
        From PowerShell
        1. Enter the following Get-AzureADMSAuthorizationPolicy
        Which will give a result like:
        Id : authorizationPolicy
        OdataType :
        Description : Used to manage
        authorization related settings across the company.
        DisplayName : Authorization Policy
        EnabledPreviewFeatures : {}
        GuestUserRoleId : 10dae51f-b6af-4016-8d66-
        8c2a99b929b3
        PermissionGrantPolicyIdsAssignedToDefaultUserRole : {user-default-legacy}
        If the GuestUserRoleID property does not equal 2af84b1e-32c8-42b7-82bc-
        daa82404023b then it is not set to most restrictive."

  desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select External Identities
        4. Select External collaboration settings
        5. Under Guest user access, set Guest user access restrictions to Guest
        user access is restricted to properties and memberships of their
        own directory objects
        6. Click Save
        Remediate from PowerShell
        1. Enter the following to update the policy ID:
        Update-MgPolicyAuthorizationPolicy -GuestUserRoleId '2af84b1e-32c8-42b7-82bc-
        daa82404023b'
        2. Check the GuestUserRoleId again:
        (Get-MgPolicyAuthorizationPolicy).GuestUserRoleId
        3. Ensure that the GuestUserRoleId is equal to the earlier entered value of
        2af84b1e-32c8-42b7-82bc-daa82404023b."

  impact 0.5
  tag nist: ['AC-3', 'AC-5', 'AC-6', 'MP-2', 'RA-2', 'AC-2(1)', 'AC-3', 'AC-2', 'AC-5', 'AC-6', 'AC-6(1)', 'AC-6(7)', 'AU-9(4)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.3', '3.7', '6.7', '6.8'] }]

  ref 'https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions#member-and-guest-users'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
  ref 'https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions'

  client_secret = input('client_secret')
  client_id = input('client_id')
  tenant_id = input('tenant_id')
  ensure_guest_users_set_most_restrictive_script = %(
     $ErrorActionPreference = "Stop"
     $password = ConvertTo-SecureString -String '#{client_secret}' -AsPlainText -Force
     $ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential('#{client_id}',$password)
     Connect-MgGraph -TenantId '#{tenant_id}' -ClientSecretCredential $ClientSecretCredential -NoWelcome
     (Get-MgPolicyAuthorizationPolicy).GuestUserRoleId
   )

  pwsh_output = powershell(ensure_guest_users_set_most_restrictive_script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe 'Ensure the output from GuestUserRoleId setting' do
    subject { pwsh_output.stdout.strip }
    it 'is set to 2af84b1e-32c8-42b7-82bc-daa82404023b' do
      expect(subject).to cmp '2af84b1e-32c8-42b7-82bc-daa82404023b'
    end
  end
end
