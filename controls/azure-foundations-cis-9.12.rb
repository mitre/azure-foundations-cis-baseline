control 'azure-foundations-cis-9.12' do
  title "Ensure that 'Remote debugging' is set to 'Off'"
  desc 'Remote Debugging allows Azure App Service to be debugged in real-time directly on the Azure environment. When remote debugging is enabled, it opens a communication channel that could potentially be exploited by unauthorized users if not properly secured.'

  desc 'rationale',
       "Disabling remote debugging on Azure App Service is primarily about enhancing security.
        Remote debugging opens a communication channel that can be exploited by attackers. By disabling it, you reduce the number of potential entry points for unauthorized access.
        If remote debugging is enabled without proper access controls, it can allow unauthorized users to connect to your application, potentially leading to data breaches or malicious code execution.
        During a remote debugging session, sensitive information might be exposed. Disabling remote debugging helps ensure that such data remains secure. This minimizes the use of remote access tools to reduce risk.control 'azure-foundations-cis-9.12' do"

  desc 'impact',
       'You will not be able to connect to your application from a remote location to diagnose and fix issues in real-time. You will not be able to step through code, set breakpoints, or inspect variables and the call stack while the application is running on the server. Remote debugging is particularly useful for diagnosing issues that only occur in the production environment. Without it, you will need to rely on logs and other diagnostic tools.'

  desc 'check',
       "Audit from Azure Portal
          1. Login to Azure Portal using https://portal.azure.com
          2. Go to App Services
          3. Click on each App
          4. Under Setting section, Click on Configuration
          5. Under the General settings tab, check the Remote debugging option. Ensure it is set to Off.
        Audit from Azure CLI
          To check remote debugging status for an existing app, run the following command,
            az webapp config show --resource-group <resource_group_name> --name <app_name> --query remoteDebuggingEnabled
          The output should be false if remote debugging is disabled.
        Audit From Powershell
          To check remote debugging status for an existing app, run the following command,
            Get-AzWebApp -ResourceGroupName <resource_group_name> -Name <app_name> |Select-Object -ExpandProperty SiteConfig
          The output of remoteDebuggingEnabled should be false if remote debugging is disabled.
        Audit from Azure Policy
          If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
            • Policy ID: cb510bfd-1cba-4d9f-a230-cb0976f4bb71 - Name: 'App Service apps should have remote debugging turned off'
            • Policy ID: 25a5046c-c423-4805-9235-e844ae9ef49b - Name: 'Configure Function apps to turn off remote debugging'"

  desc 'fix',
       "Remediate from Azure Portal
          1. Login to Azure Portal using https://portal.azure.com
          2. Go to App Services
          3. Click on each App
          4. Under Setting section, Click on Configuration
          5. Under the General settings tab, set the Remote debugging option to Off.
        Remediate from Azure CLI
          To set remote debugging status to off, run the following command
            az webapp config set --resource-group <resource_group_name> --name <app_name> --remote-debugging-enabled false
        Remediation from PowerShell
          To set remote debugging status to off, run the following command
            Set-AzWebApp -ResourceGroupName <resource_group_name> -Name <app_name> -RemoteDebuggingEnabled $false"

  impact 0.5
  tag nist: ['CM-7', 'SC-23']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['12.3'] }]

  ref 'https://learn.microsoft.com/en-us/visualstudio/debugger/remote-debugging-azure-app-service?view=vs-2022'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-posture-vulnerability-management#pv-2-audit-and-enforce-secure-configurations'

  app_script = 'Get-AzKeyVault | ConvertTo-Json'
  app_output = powershell(app_script).stdout.strip
  all_apps = json(content: app_output).params

  only_if('N/A - No Web Applications found', impact: 0) do
    !all_apps.empty?
  end

  ensure_remote_debugging_false_script = %(
    $ErrorActionPreference = "Stop"
    $filteredWebApps = Get-AzWebApp | Select-Object ResourceGroup, Name
    foreach ($webApp in $filteredWebApps) {
        $resourceGroup = $webApp.ResourceGroup
        $appName = $webApp.Name

        # Get the SiteConfig for the current web app
        $siteConfig = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $appName | Select-Object -ExpandProperty SiteConfig

        if ($siteConfig.remoteDebuggingEnabled -eq $False) {
            # Print the name of the web app
            Write-Output $appName
        }
    }
    )

  pwsh_output = powershell(ensure_remote_debugging_false_script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe "Ensure that the number of Web Applications/Resource Group combinations with SiteConfig.remoteDebuggingEnabled set to 'False'" do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following web apps have remoteDebuggingEnabled set to 'False': #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
