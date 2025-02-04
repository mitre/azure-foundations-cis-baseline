control 'azure-foundations-cis-9.3' do
    title "Ensure 'FTP State' is set to 'FTPS Only' or 'Disabled'"
    desc "By default, App Services can be deployed over FTP. If FTP is required for an essential deployment workflow, FTPS should be required for FTP login for all App Services.
        If FTPS is not expressly required for the App, the recommended setting is Disabled."

    desc 'rationale',
        "FTP is an unencrypted network protocol that will transmit data - including passwords - in clear-text. The use of this protocol can lead to both data and credential compromise, and can present opportunities for exfiltration, persistence, and lateral movement."

    desc 'impact',
        'Any deployment workflows that rely on FTP or FTPs rather than the WebDeploy or HTTPs endpoints may be affected.'

    desc 'check',
       %(Audit from Azure Portal
            1. Go to the Azure Portal
            2. Select App Services
            3. Click on an app
            4. Select Settings and then Configuration
            5. Under General Settings, for the Platform Settings, the FTP state should not be set to All allowed
        Audit from Azure CLI 
            List webapps to obtain the ids. 
                az webapp list
            List the publish profiles to obtain the username, password and ftp server url. 
                az webapp deployment list-publishing-profiles --ids <ids> 
                { 
                    "publishUrl": <URL_FOR_WEB_APP>, 
                    "userName": <USER_NAME>, 
                    "userPWD": <USER_PASSWORD>, 
                }
        Audit from PowerShell 
            List all Web Apps: 
                Get-AzWebApp
            For each app: 
                Get-AzWebApp -ResourceGroupName <resource group name> -Name <app name> | Select-Object -ExpandProperty SiteConfig
            In the output, look for the value of FtpsState. If its value is AllAllowed the setting is out of compliance. Any other value is considered in compliance with this check. 
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 399b2637-a50f-4f95-96f8-3a145476eb15 - Name: 'Function apps should require FTPS only'
                • Policy ID: 4d24b6d4-5e53-4a4f-a7f4-618fa573ee4b - Name: 'App Service apps should require FTPS only')

    desc 'fix',
       "Remediate from Azure Portal
            1. Go to the Azure Portal
            2. Select App Services
            3. Click on an app
            4. Select Settings and then Configuration
            5. Under General Settings, for the Platform Settings, the FTP state should be set to Disabled or FTPS Only
        Remediate from Azure CLI 
            For each out of compliance application, run the following choosing either 'disabled' or 'FtpsOnly' as appropriate: 
                az webapp config set --resource-group <resource group name> --name <app name> --ftps-state [disabled|FtpsOnly]
        Remediate from PowerShell 
            For each out of compliance application, run the following: 
                Set-AzWebApp -ResourceGroupName <resource group name> -Name <app name> -FtpsState <Disabled or FtpsOnly>"

    impact 0.5
    tag nist: ['AC-17(2)', 'IA-5', 'IA-5(1)', 'SC-8', 'SC-8(1)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['3.10'] }]

    ref 'https://docs.microsoft.com/en-us/azure/app-service/deploy-ftp'
    ref 'https://docs.microsoft.com/en-us/azure/app-service/overview-security'
    ref 'https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-4-encrypt-sensitive-information-in-transit'
    ref 'https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-posture-vulnerability-management#pv-7-rapidly-and-automatically-remediate-software-vulnerabilities'
    ref 'https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/create-or-update-configuration#ftpsstate'

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end