control 'azure-foundations-cis-1.1.1' do
    title "Ensure 'User consent for applications’ Is Set To ‘Allow for Verified Publishers'"
    desc "Allow users to provide consent for selected permissions when a request is coming from
        a verified publisher."

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
        6. Under User consent for applications, ensure Allow user consent for apps
        from verified publishers, for selected permissions is selected
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
        Page 76
        4. Select Consent and permissions
        5. Select User consent settings
        6. Under User consent for applications, select Allow user consent for apps
        from verified publishers, for selected permissions
        7. Select Save
        From PowerShell
        Connect-MsolService
        Set-MsolCompanyInformation --UsersPermissionToUserConsentToAppEnabled $False"

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent#configure-user-consent-to-applications'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
    ref 'https://docs.microsoft.com/en-us/powershell/module/msonline/set-msolcompanysettings?view=azureadps-1.0'
    ref 'https://docs.microsoft.com/en-us/powershell/module/msonline/get-msolcompanyinformation?view=azureadps-1.0'

    describe 'benchmark' do
        skip 'configure'
    end
end