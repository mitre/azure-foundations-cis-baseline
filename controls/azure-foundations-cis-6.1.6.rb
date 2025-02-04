control 'azure-foundations-cis-6.1.6' do
    title "Ensure that logging for Azure AppService 'HTTP logs' is enabled"
    desc "Enable AppServiceHTTPLogs diagnostic log category for Azure App Service instances to ensure all http requests are captured and centrally logged."

    desc 'rationale',
        "Capturing web requests can be important supporting information for security analysts performing monitoring and incident response activities. Once logging, these logs can be ingested into SIEM or other central aggregation point for the organization."

    desc 'impact',
        'Log consumption and processing will incur additional cost.'

    desc 'check',
       "Audit from Azure Portal
            1. Go to App Services.

            For each App Service:
                2. Under Monitoring, go to Diagnostic settings.
                3. Ensure a diagnostic setting exists that logs HTTP logs to a destination aligned to your environment's approach to log consumption (event hub, storage account, etc. dependent on what is consuming the logs such as SIEM or other log aggregation utility)."

    desc 'fix',
       "Remediate from Azure Portal
            1. Go to App Services.

            For each App Service:
                2. Under Monitoring, go to Diagnostic settings.
                3. To update an existing diagnostic setting, click Edit setting against the setting. To create a new diagnostic setting, click Add diagnostic setting and provide a name for the new setting.
                4. Check the checkbox next to HTTP logs.
                5. Configure a destination based on your specific logging consumption capability (for example Stream to an event hub and then consuming with SIEM integration for Event Hub logging).
                6. Click Save."

    impact 0.5
    tag nist: ['AU-2']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['8.7'] }]

    ref 'https://docs.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end