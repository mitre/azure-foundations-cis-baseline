control 'azure-foundations-cis-6.1.1' do
  title "Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs"
  desc 'Enable Diagnostic settings for exporting activity logs. Diagnostic settings are available for each individual resource within a subscription. Settings should be configured for all appropriate resources for your environment.'

  desc 'rationale',
       'A diagnostic setting controls how a diagnostic log is exported. By default, logs are retained only for 90 days. Diagnostic settings should be defined so that logs can be exported and stored for a longer duration in order to analyze security activities within an Azure subscription.'

  desc 'check',
       "Audit from Azure Portal
            To identify Diagnostic Settings on a subscription:
                1. Go to Monitor
                2. Click Activity Log
                3. Click Export Activity Logs
                4. Select a Subscription
                5. Ensure a Diagnostic setting exists for the selected Subscription
            To identify Diagnostic Settings on specific resources:
                1. Go to Monitoring
                2. Click Diagnostic settings
                3. Ensure a Diagnostic setting exists for all appropriate resources.
        Audit from Azure CLI
            To identify Diagnostic Settings on a subscription:
                az monitor diagnostic-settings subscription list --subscription <subscription ID>
            To identify Diagnostic Settings on a resource
                az monitor diagnostic-settings list --resource <resource Id>
        Audit from PowerShell
            To identify Diagnostic Settings on a Subscription:
                Get-AzDiagnosticSetting -SubscriptionId <subscription ID>
            To identify Diagnostic Settings on a specific resource:
                Get-AzDiagnosticSetting -ResourceId <resource ID>"

  desc 'fix',
       "Remediate from Azure Portal
            To enable Diagnostic Settings on a Subscription:
                1. Go to Monitor
                2. Click on Activity log
                3. Click on Export Activity Logs
                4. Click + Add diagnostic setting
                5. Enter a Diagnostic setting name
                6. Select Categories for the diagnostic setting
                7. Select the appropriate Destination details (this may be Log Analytics, Storage Account, Event Hub, or Partner solution)
                8. Click Save
            To enable Diagnostic Settings on a specific resource:
                1. Go to Monitoring
                2. Click Diagnostic settings
                3. Select Add diagnostic setting
                4. Enter a Diagnostic setting name
                5. Select the appropriate log, metric, and destination (this may be Log Analytics, Storage Account, Event Hub, or Partner solution)
                6. Click Save
            Repeat these step for all resources as needed.
        Remediate from Azure CLI
            To configure Diagnostic Settings on a Subscription:
                az monitor diagnostic-settings subscription create --subscription <subscription id> --name <diagnostic settings name> --location <location> <[--event-hub <event hub ID> --event-hub-auth-rule <event hub auth rule ID>] [--storage-account <storage account ID>] [--workspace <log analytics workspace ID>] --logs '<JSON encoded categories>'' (e.g. [{category:Security,enabled:true},{category:Administrative,enabled:true},{category:Alert,enabled:true},{category:Policy,enabled:true}])
            To configure Diagnostic Settings on a specific resource:
                az monitor diagnostic-settings create --subscription <subscription ID> --resource <resource ID> --name <diagnostic settings name> <[--event-hub <event hub ID> --event-hub-rule <event hub auth rule ID>] [--storage-account <storage account ID>] [--workspace <log analytics workspace ID>] --logs <resource specific JSON encoded log settings> --metrics <metric settings (shorthand|json-file|yaml-file)>
        Remediate from PowerShell
            To configure Diagnostic Settings on a subscription:
                $logCategories = @();
                $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -Category Administrative -Enabled $true
                $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -Category Security -Enabled $true
                $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -Category ServiceHealth -Enabled $true
                $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -Category Alert -Enabled $true
                $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -Category Recommendation -Enabled $true
                $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -Category Policy -Enabled $true
                $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -Category Autoscale -Enabled $true
                $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -Category ResourceHealth -Enabled $true
                New-AzSubscriptionDiagnosticSetting -SubscriptionId <subscription ID> -Name <Diagnostic settings name> <[-EventHubAuthorizationRule <event hub auth rule ID> -EventHubName <event hub name>] [-StorageAccountId <storage account ID>] [-WorkSpaceId <log analytics workspace ID>] [-MarketplacePartner ID <full ARM Marketplace resource ID>]> -Log $logCategories
            To configure Diagnostic Settings on a specific resource:
                $logCategories = @()
                $logCategories += New-AzDiagnosticSettingLogSettingsObject -Category <resource specific log category> -Enabled $true
                Repeat command and variable assignment for each Log category specific to the resource where this Diagnostic Setting will get configured.
                $metricCategories = @()
                $metricCategories += New-AzDiagnosticSettingMetricSettingsObject -Enabled $true [-Category <resource specific metric category | AllMetrics>] [-RetentionPolicyDay <Integer>] [-RetentionPolicyEnabled $true]
                Repeat command and variable assignment for each Metric category or use the 'AllMetrics' category.
                New-AzDiagnosticSetting -ResourceId <resource ID> -Name <Diagnostic settings name> -Log $logCategories -Metric $metricCategories [-EventHubAuthorizationRuleId <event hub auth rule ID> -EventHubName <event hub name>] [-StorageAccountId <storage account ID>] [-WorkspaceId <log analytics workspace ID>] [-MarketplacePartnerId <full ARM marketplace resource ID>]>    "

  impact 0.5
  tag nist: ['AU-6(3)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['8.9'] }]

  ref 'https://docs.microsoft.com/en-us/azure/monitoring-and-diagnostics/monitoring-overview-activity-logs#export-the-activity-log-with-a-log-profile'
  ref 'https://learn.microsoft.com/en-us/cli/azure/monitor/diagnostic-settings?view=azure-cli-latest'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'

  resource_script = 'Get-AzResource | ConvertTo-Json'
  resource_output = powershell(resource_script).stdout.strip
  all_resources = json(content: resource_output).params

  only_if('N/A - No Resources found', impact: 0) do
    !all_resources.empty?
  end

  activity_diagnostic_setting_exists_for_sub_script = %(
      $ErrorActionPreference = "Stop"
        $allResources = Get-AzResource
        $resourceIds = $allResources | Select-Object -ExpandProperty ResourceId
        foreach ($resourceId in $resourceIds) {
            try {
                $diagnosticSetting = Get-AzDiagnosticSetting -ResourceId $resourceId -ErrorAction Stop

                if (-not $diagnosticSetting) {
                    Write-Output "$resourceId"
                }
            } catch {
            }
        }

	)

  subscription_id = input('subscription_id')
  diagnostic_settings_subscription_output = command(%(az monitor diagnostic-settings subscription list --subscription #{subscription_id}  --query "value"))
  raise Inspec::Error, "The command output returned the following error:  #{diagnostic_settings_subscription_output.stderr}" if diagnostic_settings_subscription_output.exit_status != 0

  pwsh_output = powershell(activity_diagnostic_setting_exists_for_sub_script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe.one do
    describe 'Diagnostic settings are configured for the subscription' do
      subject { diagnostic_settings_subscription_output.stdout.strip }
      it 'has diagnostic settings configured' do
        failure_message = 'Diagnostic settings are not configured for the subscription'
        expect(subject).not_to eq('[]'), failure_message
      end
    end
    describe 'No resources without diagnostic settings' do
      subject { pwsh_output.stdout.strip }
      it 'has no resources without diagnostic settings' do
        failure_message = "The following resources do not have a diagnostic setting: #{pwsh_output.stdout.strip}"
        expect(subject).to be_empty, failure_message
      end
    end
  end
end
