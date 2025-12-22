control 'azure-foundations-cis-9.10' do
  title "Ensure that 'HTTP20enabled' is set to 'true' (if in use)"
  desc 'Periodically, newer versions are released for HTTP either due to security flaws or to include additional functionality. Using the latest HTTP version for apps to take advantage of security fixes, if any, and/or new functionalities of the newer version'

  desc 'rationale',
       "Newer versions may contain security enhancements and additional functionality. Using the latest version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected.
        HTTP 2.0 has additional performance improvements on the head-of-line blocking problem of old HTTP version, header compression, and prioritization of requests. HTTP 2.0 no longer supports HTTP 1.1's chunked transfer encoding mechanism, as it provides its own, more efficient, mechanisms for data streaming."

  desc 'impact',
       "Most modern browsers support HTTP 2.0 protocol over TLS only, while non-encrypted traffic continues to use HTTP 1.1. To ensure that client browsers connect to your app with HTTP/2, either buy an App Service Certificate for your app's custom domain or bind a third-party certificate."

  desc 'check',
       "Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com
            2. Go to App Services
            3. Click on each App
            4. Under Setting section, Click on Configuration
            5. Ensure that HTTP Version set to 2.0 version under General settings
        NOTE: Most modern browsers support HTTP 2.0 protocol over TLS only, while non-encrypted traffic continues to use HTTP 1.1. To ensure that client browsers connect to your app with HTTP/2, either buy an App Service Certificate for your app's custom domain or bind a third-party certificate.
        Audit from Azure CLI
            To check HTTP 2.0 version status for an existing app, run the following command,
                az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query http20Enabled
            The output should return true if HTTPS 2.0 traffic value is set to On.
        Audit from PowerShell
            For each application, run the following command:
                Get-AzWebApp -ResourceGroupName <app resource group> -Name <app name> |Select-Object -ExpandProperty SiteConfig
            If the value of the Http20Enabled setting is true, the application is compliant. Otherwise if the value of the Http20Enabled setting is false, the application is non-compliant.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: e2c1c086-2d84-4019-bff3-c44ccd95113c - Name: 'Function apps should use latest 'HTTP Version''
                • Policy ID: 8c122334-9d20-4eb8-89ea-ac9a705b74ae - Name: 'App Service apps should use latest 'HTTP Version''"

  desc 'fix',
       %(Remediate from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com
            2. Go to App Services
            3. Click on each App
            4. Under Setting section, Click on Configuration
            5. Set HTTP version to 2.0 under General settings
        NOTE: Most modern browsers support HTTP 2.0 protocol over TLS only, while non-encrypted traffic continues to use HTTP 1.1. To ensure that client browsers connect to your app with HTTP/2, either buy an App Service Certificate for your app's custom domain or bind a third-party certificate.
        Remediate from Azure CLI
            To set HTTP 2.0 version for an existing app, run the following command:
                az webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --http20-enabled true
        Remediate from PowerShell
            To enable HTTP 2.0 version support, run the following command:
                Set-AzWebApp -ResourceGroupName <app resource group> -Name <app name> -Http20Enabled $true
        )

  impact 0.5
  tag nist: ['SA-22']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['2.2'] }]

  ref 'https://docs.microsoft.com/en-us/azure/app-service/web-sites-configure#general-settings'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-posture-vulnerability-management#pv-3-define-and-establish-secure-configurations-for-compute-resources'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-posture-vulnerability-management#pv-6-rapidly-and-automatically-remediate-vulnerabilities'

  app_script = 'Get-AzKeyVault | ConvertTo-Json'
  app_output = powershell(app_script).stdout.strip
  all_apps = json(content: app_output).params

  only_if('N/A - No Web Applications found', impact: 0) do
    !all_apps.empty?
  end

  ensure_http20_set_to_true_script = %(
    $ErrorActionPreference = "Stop"
    $filteredWebApps = Get-AzWebApp | Select-Object ResourceGroup, Name
    foreach ($webApp in $filteredWebApps) {
        $resourceGroup = $webApp.ResourceGroup
        $appName = $webApp.Name

        # Get the SiteConfig for the current web app
        $siteConfig = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $appName | Select-Object -ExpandProperty SiteConfig

        if ($siteConfig.Http20Enabled -eq $False) {
            # Print the name of the web app
            Write-Output $appName
        }
    }
    )

  pwsh_output = powershell(ensure_http20_set_to_true_script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe "Ensure that the number of Web Applications/Resource Group combinations with SiteConfig.Http20Enabled set to 'False'" do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following web apps have Http20Enabled set to 'False': #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
