control 'azure-foundations-cis-6.4' do
  title 'Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it'
  desc "Resource Logs capture activity to the data access plane while the Activity log is a subscription-level log for the control plane. Resource-level diagnostic logs provide insight into operations that were performed within that resource itself; for example, reading or updating a secret from a Key Vault. Currently, 95 Azure resources support Azure Monitoring (See the more information section for a complete list), including Network Security Groups, Load Balancers, Key Vault, AD, Logic Apps, and CosmosDB. The content of these logs varies by resource type.
        A number of back-end services were not configured to log and store Resource Logs for certain activities or for a sufficient length. It is crucial that monitoring is correctly configured to log all relevant activities and retain those logs for a sufficient length of time. Given that the mean time to detection in an enterprise is 240 days, a minimum retention period of two years is recommended."

  desc 'rationale',
       "A lack of monitoring reduces the visibility into the data plane, and therefore an organization's ability to detect reconnaissance, authorization attempts or other malicious activity. Unlike Activity Logs, Resource Logs are not enabled by default. Specifically, without monitoring it would be impossible to tell which entities had accessed a data store that was breached. In addition, alerts for failed attempts to access APIs for Web Services or Databases are only possible when logging is enabled."

  desc 'impact',
       'Costs for monitoring varies with Log Volume. Not every resource needs to have logging enabled. It is important to determine the security classification of the data being processed by the given resource and adjust the logging based on which events need to be tracked. This is typically determined by governance and compliance requirements.'

  desc 'check',
       "%(Audit from Azure Portal
            The specific steps for configuring resources within the Azure console vary depending on resource, but typically the steps are:
                1. Go to the resource
                2. Click on Diagnostic settings
                3. In the blade that appears, click 'Add diagnostic setting'
                4. Configure the diagnostic settings
                5. Click on Save
        Audit from Azure CLI
            List all resources for a subscription
                az resource list --subscription <subscription id>
            For each resource run the following
                az monitor diagnostic-settings list --resource <resource ID>
            An empty result means a diagnostic settings is not configured for that resource. An error message means a diagnostic settings is not supported for that resource.
        Audit From Powershell
            Get a list of resources in a subscription context and store in a variable
                $resources = Get-AzResource
            Loop through each resource to determine if a diagnostic setting is configured or not.
                foreach ($resource in $resources) {$diagnosticSetting = Get-AzDiagnosticSetting -ResourceId $resource.id -ErrorAction 'SilentlyContinue'; if ([string]::IsNullOrEmpty($diagnosticSetting)) {$message = 'Diagnostic Settings not configured for resource: ' + $resource.Name;Write-Output $message}else{$diagnosticSetting}}
            A result of Diagnostic Settings not configured for resource: <resource name> means a diagnostic settings is not configured for that resource. Otherwise, the output of the above command will show configured Diagnostic Settings for a resource.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: cf820ca0-f99e-4f3e-84fb-66e913812d21 - Name: 'Resource logs in Key Vault should be enabled'
                • Policy ID: 91a78b24-f231-4a8a-8da9-02c35b2b6510 - Name: 'App Service apps should have resource logs enabled'
                • Policy ID: 428256e6-1fac-4f48-a757-df34c2b3336d - Name: 'Resource logs in Batch accounts should be enabled'
                • Policy ID: 057ef27e-665e-4328-8ea3-04b3122bd9fb - Name: 'Resource logs in Azure Data Lake Store should be enabled'
                • Policy ID: c95c74d9-38fe-4f0d-af86-0c7d626a315c - Name: 'Resource logs in Data Lake Analytics should be enabled'
                • Policy ID: 83a214f7-d01a-484b-91a9-ed54470c9a6a - Name: 'Resource logs in Event Hub should be enabled'
                • Policy ID: 383856f8-de7f-44a2-81fc-e5135b5c2aa4 - Name: 'Resource logs in IoT Hub should be enabled'
                • Policy ID: 34f95f76-5386-4de7-b824-0d8478470c9d - Name: 'Resource logs in Logic Apps should be enabled
                • Policy ID: b4330a05-a843-4bc8-bf9a-cacce50c67f4 - Name: 'Resource logs in Search services should be enabled'
                • Policy ID: f8d36e2f-389b-4ee4-898d-21aeb69a0f45 - Name: 'Resource logs in Service Bus should be enabled'
                • Policy ID: f9be5368-9bf5-4b84-9e0a-7850da98bb46 - Name: 'Resource logs in Azure Stream Analytics should be enabled')"

  desc 'fix',
       "%(Azure Subscriptions should log every access and operation for all resources. Logs should be sent to Storage and a Log Analytics Workspace or equivalent third-party system. Logs should be kept in readily-accessible storage for a minimum of one year, and then moved to inexpensive cold storage for a duration of time as necessary. If retention policies are set but storing logs in a Storage Account is disabled (for example, if only Event Hubs or Log Analytics options are selected), the retention policies have no effect. Enable all monitoring at first, and then be more aggressive moving data to cold storage if the volume of data becomes a cost concern.
        Remediate from Azure Portal
            The specific steps for configuring resources within the Azure console vary depending on resource, but typically the steps are:
                1. Go to the resource
                2. Click on Diagnostic settings
                3. In the blade that appears, click 'Add diagnostic setting'
                4. Configure the diagnostic settings
                5. Click on Save
        Remediate from Azure CLI
            For each resource, run the following making sure to use a resource appropriate JSON encoded category for the --logs option.
                az monitor diagnostic-settings create --name <diagnostic settings name> --resource <resource ID> --logs '[{category:<resource specific category>,enabled:true,rentention-policy:{enabled:true,days:180}}]' --metrics '[{category:AllMetrics,enabled:true,retention-policy:{enabled:true,days:180}}]' <[--event-hub <event hub ID> --event-hub-rule <event hub auth rule ID> | --storage-account <storage account ID> |--workspace <log analytics workspace ID> | --marketplace-partner-id <full resource ID of third-party solution>]>]
        Remediate From Powershell
            Create the log settings object
                $logSettings = @()
                $logSettings += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -RetentionPolicyDay 180 -RetentionPolicyEnabled $true -Category <resource specific category>
                $logSettings += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -RetentionPolicyDay 180 -RetentionPolicyEnabled $true -Category <resource specific category number 2>
            Create the metric settings object
                $metricSettings = @()
                $metricSettings += New-AzDiagnosticSettingMetricSettingsObject -Enabled $true -RetentionPolicyDay 180 -RetentionPolicyEnabled $true -Category AllMetrics
            Create the diagnostic setting for a specific resource
                New-AzDiagnosticSetting -Name '<diagnostic settings name>' -ResourceId <resource ID> -Log $logSettings -Metric $metricSettings)'"

  impact 0.5
  tag nist: ['AU-3', 'AU-3(1)', 'AU-7', 'AU-12', 'AU-6(3)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['8.5', '8.9'] }]

  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-5-centralize-security-log-management-and-analysis'
  ref 'https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/monitor-azure-resource'
  ref 'https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/resource-logs-categories'
  ref 'https://docs.microsoft.com/en-us/azure/security/fundamentals/log-audit'
  ref 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/collect-activity-logs'
  ref 'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-logging'
  ref 'https://docs.microsoft.com/en-us/cli/azure/monitor/diagnostic-settings?view=azure-cli-latest'
  ref 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-logs-overview'
  ref 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-logs-schema'
  ref 'https://docs.microsoft.com/en-us/azure/cdn/cdn-azure-diagnostic-logs'

  subscription_id = input('subscription_id')

  describe "Diagnostic Settings across all resources in Subscription #{subscription_id}" do
    script = <<-EOH
            Set-AzContext -Subscription #{subscription_id} | Out-Null
            $resources = Get-AzResource
            foreach ($resource in $resources) {
            $diagnosticSetting = Get-AzDiagnosticSetting -ResourceId $resource.id -ErrorAction SilentlyContinue
            if ([string]::IsNullOrEmpty($diagnosticSetting)) {
                Write-Output "Diagnostic Settings not configured for resource: $($resource.Name)"
            }
            }
    EOH

    describe powershell(script) do
      its('stdout') { should_not match(/Diagnostic Settings not configured for resource:/) }
    end
  end
end
