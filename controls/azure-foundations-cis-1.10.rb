control 'azure-foundations-cis-1.10' do
    title "Ensure `User consent for applications` is set to `Do not allow user consent`"
    desc "Require administrators to provide consent for applications before use."

    desc 'rationale',
        "If Microsoft Entra ID is running as an identity provider for third-party applications,
        permissions and consent should be limited to administrators or pre-approved. Malicious
        applications may attempt to exfiltrate data or abuse privileged user accounts."

    desc 'impact',
        "Enforcing this setting may create additional requests that administrators need to review."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Enterprise Applications
        4. Select Consent and permissions
        5. Select User consent settings
        6. Ensure User consent for applications is set to Do not allow user consent
        From PowerShell
        Connect-MsolService
        Get-MsolCompanyInformation | Select-Object
        UsersPermissionToUserConsentToAppEnabled
        Command should return UsersPermissionToUserConsentToAppEnabled with the value of
        False"

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Enterprise Applications
        4. Select Consent and permissions
        5. Select User consent settings
        Page 74
        6. Set User consent for applications to Do not allow user consent
        7. Click save"

    impact 0.5
    tag nist: ['CM-7(2)','CM-8(3)','CM-10','CM-11','IA-4','IA-5','AC-1','AC-2','AC-2(1)','AC-2(1)','AC-3']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['2.3','6.1','6.7'] }]

    ref 'https://nicksnettravels.builttoroam.com/post/2017/01/24/Admin-Consent-for-Permissions-in-Azure-Active-Directory.aspx'
    ref 'https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent#configure-user-consent-to-applications'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'

    describe 'benchmark' do
        skip 'configure'
    end
end