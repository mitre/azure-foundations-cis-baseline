control 'azure-foundations-cis-6.3.1' do
  title 'Ensure Application Insights are Configured'
  desc 'Application Insights within Azure act as an Application Performance Monitoring solution providing valuable data into how well an application performs and additional information when performing incident response. The types of log data collected include application metrics, telemetry data, and application trace logging data providing organizations with detailed information about application activity and application transactions. Both data sets help organizations adopt a proactive and retroactive means to handle security and performance related metrics within their modern applications.'

  desc 'rationale',
       "Configuring Application Insights provides additional data not found elsewhere within Azure as part of a much larger logging and monitoring program within an organization's Information Security practice. The types and contents of these logs will act as both a potential cost saving measure (application performance) and a means to potentially confirm the source of a potential incident (trace logging). Metrics and Telemetry data provide organizations with a proactive approach to cost savings by monitoring an application's performance, while the trace logging data provides necessary details in a reactive incident response scenario by helping organizations identify the potential source of an incident within their application."

  desc 'impact',
       'Because Application Insights relies on a Log Analytics Workspace, an organization will incur additional expenses when using this service.'

  desc 'check',
       "%(Audit from Azure Portal
            1. Navigate to Application Insights
            2. Ensure an Application Insights service is configured and exists.
        Audit from Azure CLI
            Note: The application-insights extension to Azure CLI is currently in Preview Add the application-insights extension.
                az extension add --name application-insights
                az monitor app-insights component show --query '[].{ID:appId, Name:name, Tenant:tenantId, Location:location, Provisioning_State:provisioningState}'
                Ensure the above command produces output, otherwise Application Insights has not been configured.
        Audit From Powershell
            Get-AzApplicationInsights|select location,name,appid,provisioningState,tenantid
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: fa9cd53d-cb8f-464e-84f1-7b1490fd21c6 - Name: 'Deploy Diagnostic Settings for Application Insights to Log Analytics workspace')"

  desc 'fix',
       "Remediate from Azure Portal
            1. Navigate to Application Insights
            2. Under the Basics tab within the PROJECT DETAILS section, select the Subscription
            3. Select the Resource group
            4. Within the INSTANCE DETAILS, enter a Name
            5. Select a Region
            6. Next to Resource Mode, select Workspace-based
            7. Within the WORKSPACE DETAILS, select the Subscription for the log analytics workspace
            8. Select the appropriate Log Analytics Workspace
            9. Click Next:Tags >
            10. Enter the appropriate Tags as Name, Value pairs.
            11. Click Next:Review+Create
            12. Click Create
        Remediate from Azure CLI
            az monitor app-insights component create --app <app name> --resource-group <resource group name> --location <location> --kind 'web' --retention-time <INT days to retain logs> --workspace <log analytics workspace ID> --subscription <subscription ID>
        Remediate From Powershell
            New-AzApplicationInsights -Kind 'web' -ResourceGroupName <resource group name> -Name <app insights name> -location <location> -RetentionInDays <INT days to retain logs> -SubscriptionID <subscription ID> -WorkspaceResourceId <log analytics workspace ID>"

  impact 0.5
  tag nist: ['AU-2', 'AU-7', 'AU-12']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['8.2'] }]

  ref 'https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview'

  insight_script = 'Get-AzApplicationInsights | ConvertTo-Json -Depth 10'
  insight_output = powershell(insight_script).stdout.strip
  all_insights = json(content: insight_output).params

  only_if('N/A - No Application Insights found', impact: 0) do
    case all_insights
    when Array
      !all_insights.empty?
    when Hash
      !all_insights.empty?
    else
      false
    end
  end

  subscription_id = input('subscription_id')

  describe "Application Insights configuration for subscription" do
    script = <<-EOH
            $ErrorActionPreference = "Stop"
            Set-AzContext -Subscription #{subscription_id} | Out-Null
            Get-AzApplicationInsights | select location,name,appid,provisioningState,tenantid
    EOH

    pwsh_output = powershell(script)
    raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

    describe pwsh_output do
      its('stdout.strip') { should_not be_empty }
    end
  end
end
