control 'azure-foundations-cis-2.17' do
  title "Ensure That 'Restrict access to Microsoft Entra admin center' is Set to 'Yes'"
  desc "Restrict access to the Microsoft Entra ID administration center to administrators only.
        NOTE: This only affects access to the Entra ID administrator's web portal. This setting
        does not prohibit privileged users from using other methods such as Rest API or
        Powershell to obtain sensitive information from Microsoft Entra ID."

  desc 'rationale',
       "The Microsoft Entra ID administrative center has sensitive data and permission settings.
        All non-administrators should be prohibited from accessing any Microsoft Entra ID data
        in the administration center to avoid exposure."

  desc 'impact',
       'All administrative tasks will need to be done by Administrators, causing additional overhead in management of users and resources.'

  desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Then Users
        4. Select User settings
        5. Ensure that Restrict access to Microsoft Entra admin center is set to Yes"

  desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Users
        4. Under Manage, select User settings
        5. Under Administration centre, set Restrict access to Microsoft Entra
        admin center to Yes
        6. Click Save"

  impact 0.5
  tag nist: ['AC-6(2)', 'AC-6(5)', 'AC-2', 'AC-2(1)', 'AC-2', 'AC-5', 'AC-6', 'AC-6(1)', 'AC-6(7)', 'AU-9(4)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['5.4', '6.8'] }]

  ref 'https://docs.microsoft.com/en-us/azure/active-directory/active-directory-assign-admin-roles-azure-portal'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'

  describe "Ensure That 'Restrict access to Microsoft Entra admin center' is Set to 'Yes'" do
    skip 'The check for this control needs to be done manually'
  end
end
