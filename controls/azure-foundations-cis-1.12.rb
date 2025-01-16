control 'azure-foundations-cis-1.12' do
    title "Ensure that 'Users can add gallery apps to My Apps' is set to 'No'"
    desc "Require administrators to provide consent for the apps before use."

    desc 'rationale',
        "Unless Microsoft Entra ID is running as an identity provider for third-party applications,
        do not allow users to use their identity outside of your cloud environment. User profiles
        contain private information such as phone numbers and email addresses which could
        then be sold off to other third parties without requiring any further consent from the user."

    desc 'impact',
        "Can cause additional requests to administrators that need to be fulfilled quite often."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Then Enterprise applications
        4. Select User settings
        5. Ensure that Users can add gallery apps to My Apps is set to No"

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Then Enterprise applications
        4. Select User settings
        5. Set Users can add gallery apps to My Apps to No"

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://blogs.msdn.microsoft.com/exchangedev/2014/06/05/managing-user-consent-for-applications-using-office-365-apis/'
    ref 'https://nicksnettravels.builttoroam.com/post/2017/01/24/Admin-Consent-for-Permissions-in-Azure-Active-Directory.aspx'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'

    describe 'benchmark' do
        skip 'configure'
    end
end