control 'azure-foundations-cis-9.1' do
  title "Ensure 'HTTPS Only' is set to `On`"
  desc 'Azure App Service allows apps to run under both HTTP and HTTPS by default. Apps can be accessed by anyone using non-secure HTTP links by default. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. It is recommended to enforce HTTPS-only traffic.'

  desc 'rationale',
       'Enabling HTTPS-only traffic will redirect all non-secure HTTP requests to HTTPS ports. HTTPS uses the TLS/SSL protocol to provide a secure connection which is both encrypted and authenticated. It is therefore important to support HTTPS for the security benefits.'

  desc 'impact',
       'When it is enabled, every incoming HTTP request is redirected to the HTTPS port. This means an extra level of security will be added to the HTTP requests made to the app.'

  desc 'check',
       "Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com
            2. Go to App Services
            3. For each App Service
            4. Under Setting section, click on Configuration
            5. Under the General Settings tab, ensure that HTTPS Only is set to On under Platform Settings
        Audit from Azure CLI
            To check HTTPS-only traffic value for an existing app, run the following command,
                az webapp show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query httpsOnly
            The output should return true if HTTPS-only traffic value is set to On.
        Audit from PowerShell
            List all the web apps configured within the subscription.
                Get-AzWebApp | Select-Object ResourceGroup, Name, HttpsOnly
            For each web app review the HttpsOnly setting and make sure it is set to True.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: a4af4a39-4135-47fb-b175-47fbdf85311d - Name: 'App Service apps should only be accessible over HTTPS'"

  desc 'fix',
       "Remediate from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com
            2. Go to App Services
            3. For each App Service
            4. Under Setting section, click on Configuration
            5. Under the General Settings tab, set HTTPS Only to On under Platform Settings
        Remediate from Azure CLI
            To set HTTPS-only traffic value for an existing app, run the following command:
                az webapp update --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --set httpsOnly=true
        Remediate from PowerShell
            Set-AzWebApp -ResourceGroupName <RESOURCE_GROUP_NAME> -Name <APP_NAME> -HttpsOnly $true"

  impact 0.5
  tag nist: ['AC-17(2)', 'IA-5', 'IA-5(1)', 'SC-8', 'SC-8(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.10'] }]

  ref 'https://learn.microsoft.com/en-us/azure/app-service/overview-security?source=recommendations#https-and-certificates'
  ref 'https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-3-encrypt-sensitive-data-in-transit'
  ref 'https://learn.microsoft.com/en-us/powershell/module/az.websites/set-azwebapp'
  ref 'https://techcommunity.microsoft.com/t5/azure-paas-blog/enable-https-setting-on-azure-app-service-using-azure-policy/ba-p/3286603'

  app_script = 'Get-AzKeyVault | ConvertTo-Json'
  app_output = powershell(app_script).stdout.strip
  all_apps = json(content: app_output).params

  only_if('N/A - No Web Applications found', impact: 0) do
    case all_apps
    when Array
      !all_apps.empty?
    when Hash
      !all_apps.empty?
    else
      false
    end
  end

  https_only_set_on_script = %(
    $ErrorActionPreference = "Stop"
    $webApps = Get-AzWebApp
    # Filter web apps where HttpsOnly is not set to True
    $nonHttpsOnlyWebApps = $webApps | Where-Object { $_.HttpsOnly -ne $true }
    if ($nonHttpsOnlyWebApps.Count -gt 0) {
    # Iterate over each web app that doesn't have HttpsOnly set to True
        foreach ($webApp in $nonHttpsOnlyWebApps) {
            $resourceGroupName = $webApp.ResourceGroup
            $webAppName = $webApp.Name
            # Print the web app details
            Write-Host $webAppName
        }
    }
  )
  pwsh_output = powershell(https_only_set_on_script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe "Ensure the number of web apps that have HttpsOnly setting set to 'False'" do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following web apps have HttpsOnly setting set to 'False': #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
