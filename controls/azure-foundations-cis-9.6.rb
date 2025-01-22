control 'azure-foundations-cis-9.6' do
    title "Ensure that 'Basic Authentication' is 'Disabled'"
    desc "Basic Authentication provides the ability to create identities and authentication for an App Service without a centralized Identity Provider. For a more effective, capable, and secure solution for Identity, Authentication, Authorization, and Accountability, a centralized Identity Provider such as Entra ID is strongly advised."

    desc 'rationale',
        "Basic Authentication introduces an identity silo which can produce privileged access to a resource. This can be exploited in numerous ways and represents a significant vulnerability and attack vector."

    desc 'impact',
        'An Identity Provider that can be used by the App Service for authenticating users is required.'
        
    desc 'check',
       %(
       Audit from Azure Portal
            1. Search for, and open App Services from the search bar.
            2. For each App Service listed:
            3. Click on the App Service name.
            4. Under the Settings menu item, click on Configuration
            5. Under the General settings tab, scroll down to locate the two Basic Auth settings:
                • SCM Basic Auth Publishing Credentials
                • FTP Basic Auth Publishing Credentials
            Both radio buttons should indicate a status of Off. Repeat this procedure for each App Service.
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 871b205b-57cf-4e1e-a234-492616998bf7 - Name: 'App Service apps should have local authentication methods disabled for FTP deployments'
                • Policy ID: aede300b-d67f-480a-ae26-4b3dfb1a1fdc - Name: 'App Service apps should have local authentication methods disabled for SCM site deployments'
       )

    desc 'fix',
       %(
       Remediate from Azure Portal
            1. Search for, and open App Services from the search bar.
            2. For each App Service listed:
            3. Click on the App Service name.
            4. Under the Settings menu item, click on Configuration
            5. Under the General settings tab, scroll down to locate the two Basic Auth settings:
                • Set the SCM Basic Auth Publishing Credentials radio button to Off
                • Set the FTP Basic Auth Publishing Credentials radio button to Off
            CAUTION: The new settings are not yet applied. Applying them may cause your App Service resource to restart - proceed with caution. Click the Save button, then click Continue to apply the updated configuration. Repeat this procedure for each App Service.)

    impact 0.5
    tag nist: ['AC-2(1)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['5.6'] }]

    ref 'https://learn.microsoft.com/en-us/azure/app-service/configure-basic-auth-disable?tabs=portal'

    describe 'benchmark' do
        skip 'configure'
    end
end