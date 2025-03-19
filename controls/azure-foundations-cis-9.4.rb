control 'azure-foundations-cis-9.4' do
  title 'Ensure Web App is using the latest version of TLS encryption'
  desc 'The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS. App service allows TLS 1.2 by default, which is the recommended TLS level by industry standards such as PCI DSS.'

  desc 'rationale',
       'App service currently allows the web app to set TLS versions 1.0, 1.1 and 1.2. It is highly recommended to use the latest TLS 1.2 version for web app secure connections.'

  desc 'check',
       "Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com
            2. Go to App Services
            3. Click on each App
            4. Under Setting section, Click on TLS/SSL settings
            5. Under the Bindings pane, ensure that Minimum TLS Version set to 1.2 under Protocol Settings
        Audit from Azure CLI
            To check TLS Version for an existing app, run the following command,
                az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query minTlsVersion
                The output should return 1.2 if TLS Version is set to 1.2 (Which is currently the latest version).
            Audit From Powershell List all web apps.
                    Get-AzWebApp
                For each web app run the following command.
                    Get-AzWebApp -ResourceGroupName <RESOURCE_GROUP_NAME> -Name <APP_NAME> |Select-Object -ExpandProperty SiteConfig
                    Make sure the minTlsVersion is set to at least 1.2.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: f9d614c5-c173-4d56-95a7-b4437057d193 - Name: 'Function apps should use the latest TLS version'
                • Policy ID: f0e6e85b-9b9f-4a4b-b67b-f730d42f1b0b - Name: 'App Service apps should use the latest TLS version'"

  desc 'fix',
       "Remediate from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com
            2. Go to App Services
            3. Click on each App
            4. Under Setting section, Click on SSL settings
            5. Under the Bindings pane, set Minimum TLS Version to 1.2 under Protocol Settings section
        Remediate from Azure CLI
            To set TLS Version for an existing app, run the following command:
                az webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --min-tls-version 1.2
        Remediate From Powershell
            Set-AzWebApp -ResourceGroupName <RESOURCE_GROUP_NAME> -Name <APP_NAME> -MinTlsVersion 1.2"

  impact 0.5
  tag nist: ['AC-17(2)', 'IA-5', 'IA-5(1)', 'SC-8', 'SC-8(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.10'] }]

  ref 'https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-ssl#enforce-tls-versions'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-3-encrypt-sensitive-data-in-transit'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-8-detect-and-disable-insecure-services-and-protocols'
  ref 'https://docs.microsoft.com/en-us/powershell/module/az.websites/set-azwebapp?view=azps-8.1.0'

  ensure_web_app_using_latest_tls_script = %(
        $filteredWebApps = Get-AzWebApp | Select-Object ResourceGroup, Name
        foreach ($webApp in $filteredWebApps) {
            $resourceGroup = $webApp.ResourceGroup
            $appName = $webApp.Name

            # Get the SiteConfig for the current web app
            $siteConfig = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $appName | Select-Object -ExpandProperty SiteConfig
            if ($siteConfig.MinTlsVersion -lt 1.2) {
                # Print the name of the web app
                Write-Output $appName
            }
        }
    )

  pwsh_output = powershell(ensure_web_app_using_latest_tls_script)

  describe 'Ensure that the number of Web Applications/Resource Group combinations with SiteConfig.MinTlsVersion less than 1.2' do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following web apps have TLS version less than 1.2: #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
