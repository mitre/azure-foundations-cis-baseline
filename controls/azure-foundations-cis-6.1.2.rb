control 'azure-foundations-cis-6.1.2' do
  title 'Ensure Diagnostic Setting captures appropriate categories'
  desc "Prerequisite: A Diagnostic Setting must exist. If a Diagnostic Setting does not exist, the navigation and options within this recommendation will not be available. Please review the recommendation at the beginning of this subsection titled: 'Ensure that a 'Diagnostic Setting' exists.'
        The diagnostic setting should be configured to log the appropriate activities from the control/management plane."

  desc 'rationale',
       'A diagnostic setting controls how the diagnostic log is exported. Capturing the diagnostic setting categories for appropriate control/management plane activities allows proper alerting.'

  desc 'check',
       "Audit from Azure Portal
            1. Go to Monitor.
            2. Click Activity log.
            3. Click on Export Activity Logs.
            4. Select the appropriate Subscription.
            5. Click Edit setting next to a diagnostic setting.
            6. Ensure that the following categories are checked: Administrative, Alert, Policy, and Security.
        Audit from Azure CLI
            Ensure the categories 'Administrative', 'Alert', 'Policy', and 'Security' set to: 'enabled: true'
                az monitor diagnostic-settings subscription list --subscription <subscription ID>
        Audit from PowerShell
            Ensure the categories Administrative, Alert, Policy, and Security are set to Enabled:True
                Get-AzSubscriptionDiagnosticSetting -Subscription <subscriptionID>
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 3b980d31-7904-4bb7-8575-5665739a8052 - Name: 'An activity log alert should exist for specific Security operations'
                • Policy ID: b954148f-4c11-4c38-8221-be76711e194a - Name: 'An activity log alert should exist for specific Administrative operations'
                • Policy ID: c5447c04-a4d7-4ba8-a263-c9ee321a6858 - Name: 'An activity log alert should exist for specific Policy operations'"

  desc 'fix',
       "Remediate from Azure Portal
            1. Go to Monitor.
            2. Click Activity log.
            3. Click on Export Activity Logs.
            4. Select the Subscription from the drop down menu.
            5. Click Edit setting next to a diagnostic setting.
            6. Check the following categories: Administrative, Alert, Policy, and Security.
            7. Choose the destination details according to your organization's needs.
            8. Click Save.
        Remediate from Azure CLI
            az monitor diagnostic-settings subscription create --subscription <subscription id> --name <diagnostic settings name> --location <location> <[--event-hub <event hub ID> --event-hub-auth-rule <event hub auth rule ID>] [--storage-account <storage account ID>] [--workspace <log analytics workspace ID>] --logs '[{category:Security,enabled:true},{category:Administrative,enabled:true},{category:Alert,enabled:true},{category:Policy,enabled:true}]'
        Remediate from PowerShell
            $logCategories = @();
            $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -Category Administrative -Enabled $true
            $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -Category Security -Enabled $true
            $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -Category Alert -Enabled $true
            $logCategories += New-AzDiagnosticSettingSubscriptionLogSettingsObject -Category Policy -Enabled $true
            New-AzSubscriptionDiagnosticSetting -SubscriptionId <subscription ID> -Name <Diagnostic settings name> <[-EventHubAuthorizationRule <event hub auth rule ID> -EventHubName <event hub name>] [-StorageAccountId <storage account ID>] [-WorkSpaceId <log analytics workspace ID>] [-MarketplacePartner ID <full ARM Marketplace resource ID>]> -Log $logCategories"

  impact 0.5
  tag nist: ['AU-3', 'AU-3(1)', 'AU-7', 'AU-12']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['8.5'] }]

  ref 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings'
  ref 'https://docs.microsoft.com/en-us/azure/azure-monitor/samples/resource-manager-diagnostic-settings'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'
  ref 'https://learn.microsoft.com/en-us/cli/azure/monitor/diagnostic-settings?view=azure-cli-latest'
  ref 'https://learn.microsoft.com/en-us/powershell/module/az.monitor/new-azsubscriptiondiagnosticsetting?view=azps-9.2.0'

  subscription_id = input('subscription_id')

  required_categories = ['Administrative', 'Alert', 'Policy', 'Security']

  diag_script = "az monitor diagnostic-settings subscription list --subscription #{subscription_id} -o json"
  diag_output = command(diag_script).stdout.strip
  diag_settings = json(content: diag_output).params['value'] || []
  only_if('N/A - No subscription diagnostic settings found', impact: 0) do
    !diag_settings.empty?
  end

  failures = []
  unless diag_settings.empty?
    diag_settings.each do |diag_setting|
      diag_setting_name = diag_setting['name']
      required_categories.each do |category|
        log_entry = diag_setting['logs'].find { |log| log['category'] == category }
        failures << "#{diag_setting_name}/#{category}" unless log_entry && log_entry['enabled']
      end
    end
  end

  describe 'Subscription diagnostic settings with missing categories' do
    subject { failures }
    it { should be_empty }
  end
end
