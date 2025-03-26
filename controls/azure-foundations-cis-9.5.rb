control 'azure-foundations-cis-9.5' do
  title 'Ensure that Register with Entra ID is enabled on App Service'
  desc 'Managed service identity in App Service provides more security by eliminating secrets from the app, such as credentials in the connection strings. When registering an App Service with Entra ID, the app will connect to other Azure services securely without the need for usernames and passwords.'

  desc 'rationale',
       'App Service provides a highly scalable, self-patching web hosting service in Azure. It also provides a managed identity for apps, which is a turn-key solution for securing access to Azure SQL Database and other Azure services.'

  desc 'check',
       "Audit from Azure Portal
            1. from Azure Portal open the Portal Menu in the top left
            2. Go to App Services
            3. Click on each App
            4. Under the Setting section, Click on Identity
            5. Under the System assigned pane, ensure that Status set to On
        Audit from Azure CLI
            To check Register with Entra ID feature status for an existing app, run the following command,
                az webapp identity show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query principalId
                The output should return unique Principal ID. If no output for the above command then Register with Entra ID is not set.
        Audit From Powershell
            List the web apps.
                Get-AzWebApp
            For each web app run the following command.
                Get-AzWebapp -ResourceGroupName <app resource group> -Name <app name>
                Make sure the Identity setting contains a unique Principal ID
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 0da106f2-4ca3-48e8-bc85-c638fe6aea8f - Name: 'Function apps should use managed identity'
                • Policy ID: 2b9ad585-36bc-4615-b300-fd4435808332 - Name: 'App Service apps should use managed identity'"

  desc 'fix',
       "Remediate from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com
            2. Go to App Services
            3. Click on each App
            4. Under Setting section, Click on Identity
            5. Under the System assigned pane, set Status to On
        Remediate from Azure CLI
            To register with Entra ID for an existing app, run the following command:
                az webapp identity assign --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME>
        Remediate From Powershell To register with Entra ID for an existing app, run the following command:
            Set-AzWebApp -AssignIdentity $True -ResourceGroupName <resource_Group_Name> -Name <App_Name>"

  impact 0.5
  tag nist: ['AC-2(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['5.6'] }]

  ref 'https://docs.microsoft.com/en-gb/azure/app-service/app-service-web-tutorial-connect-msi'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-1-use-centralized-identity-and-authentication-system'

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

  ensure_register_entra_id_enabled_app_service_script = %(
        $filteredWebApps = Get-AzWebApp | Select-Object ResourceGroup, Name
        $unique_id_tracker = @{}
        foreach ($webApp in $filteredWebApps) {
            $resourceGroup = $webApp.ResourceGroup
            $appName = $webApp.Name

            # Get the SiteConfig for the current web app
            $appData = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $appName
            $principal_id = $appData.Identity
            if ($principal_id -eq $null){
                Write-Output "$appName has Null Principal ID"
            }
            else{
                if ($unique_id_tracker.ContainsKey($principal_id)) {
                    Write-Output "$appName has the same Principal ID as $($unique_id_tracker[$principal_id])"
                } else {
                    $unique_id_tracker[$principal_id] = $appName
                }
            }
        }
    )

  pwsh_output = powershell(ensure_register_entra_id_enabled_app_service_script)

  describe 'Ensure that the number of Web Applications/Resource Group combinations without Unique Identity Principal ID' do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "Error: #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
