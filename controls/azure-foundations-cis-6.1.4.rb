control 'azure-foundations-cis-6.1.4' do
    title "Ensure that logging for Azure Key Vault is 'Enabled'"
    desc "Enable AuditEvent logging for key vault instances to ensure interactions with key vaults are logged and available."

    desc 'rationale',
        "Monitoring how and when key vaults are accessed, and by whom, enables an audit trail of interactions with confidential information, keys, and certificates managed by Azure Key Vault. Enabling logging for Key Vault saves information in a user provided destination of either an Azure storage account or Log Analytics workspace. The same destination can be used for collecting logs for multiple Key Vaults."

    desc 'check',
       %(Audit from Azure CLI 
            List all key vaults 
                az keyvault list
            For each keyvault id 
                az monitor diagnostic-settings list --resource <id>
            Ensure that storageAccountId reflects your desired destination and that categoryGroup and enabled are set as follows in the sample outputs below. 
                "logs": [ 
                { 
                    "categoryGroup": "audit", 
                    "enabled": true, 
                }, 
                { 
                    "categoryGroup": "allLogs", 
                    "enabled": true, 
                }
        Audit from PowerShell 
            List the key vault(s) in the subscription 
                Get-AzKeyVault
            For each key vault, run the following: 
                Get-AzDiagnosticSetting -ResourceId <key_vault_id>
            Ensure that StorageAccountId, ServiceBusRuleId, MarketplacePartnerId, or WorkspaceId is set as appropriate. Also, ensure that enabled is set to true, and that categoryGroup reflects both audit and allLogs category groups.
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: cf820ca0-f99e-4f3e-84fb-66e913812d21 - Name: 'Resource logs in Key Vault should be enabled')

    desc 'fix',
       'Remediate from Azure Portal
            1. Go to Key vaults.
            2. Select a Key vault.
            3. Under Monitoring, select Diagnostic settings.
            4. Click Edit setting to update an existing diagnostic setting, or Add diagnostic setting to create a new one.
            5. If creating a new diagnostic setting, provide a name.
            6. Configure an appropriate destination.
            7. Under Category groups, check audit and allLogs.
            8. Click Save.
        Remediate from Azure CLI 
            To update an existing Diagnostic Settings 
                az monitor diagnostic-settings update --name "<diagnostic_setting_name>" --resource <key_vault_id>
            To create a new Diagnostic Settings
                az monitor diagnostic-settings create --name "<diagnostic_setting_name>" --resource <key_vault_id> --logs "[{category:audit,enabled:true},{category:allLogs,enabled:true}]" --metrics "[{category:AllMetrics,enabled:true}]" <[--event-hub <event_hub_ID> --event-hub-rule <event_hub_auth_rule_ID> | --storage-account <storage_account_ID> |--workspace <log_analytics_workspace_ID> | --marketplace-partner-id <solution_resource_ID>]>
        Remediate from PowerShell 
            Create the Log settings object 
                $logSettings = @() 
                $logSettings += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category audit 
                $logSettings += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -Category allLogs
            Create the Metric settings object 
                $metricSettings = @() 
                $metricSettings += New-AzDiagnosticSettingMetricSettingsObject -Enabled $true -Category AllMetrics
            Create the Diagnostic Settings for each Key Vault 
                New-AzDiagnosticSetting -Name "<diagnostic_setting_name>" -ResourceId <key_vault_id> -Log $logSettings -Metric $metricSettings [-StorageAccountId <storage_account_ID> | -EventHubName <event_hub_name> -EventHubAuthorizationRuleId <event_hub_auth_rule_ID> | -WorkSpaceId <log analytics workspace ID> | -MarketPlacePartnerId <full resource ID for third-party solution>]'

    impact 0.5
    tag nist: ['AU-3', 'AU-3(1)', 'AU-7', 'AU-12']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['8.5'] }]

    ref 'https://docs.microsoft.com/en-us/azure/key-vault/general/howto-logging'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-8-ensure-security-of-key-and-certificate-repository'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end