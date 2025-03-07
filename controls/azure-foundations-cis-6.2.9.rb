control 'azure-foundations-cis-6.2.9' do
  title 'Ensure that Activity Log Alert exists for Create or Update Public IP Address rule'
  desc 'Create an activity log alert for the Create or Update Public IP Addresses rule'

  desc 'rationale',
       'Monitoring for Create or Update Public IP Address events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.'

  desc 'impact',
       'There will be a substantial increase in log size if there are a large number of administrative actions on a server.'

  desc 'check',
       "%(Audit from Azure Portal
            1. Navigate to the Monitor blade.
            2. Click on Alerts.
            3. In the Alerts window, click on Alert rules.
            4. Ensure an alert rule exists where the Condition column contains Operation name=Microsoft.Network/publicIPAddresses/write.
            5. Click on the Alert Name associated with the previous step.
            6. Ensure the Condition panel displays the text Whenever the Activity Log has an event with Category='Administrative', Operation name='Create or Update Public Ip Address' and does not filter on Level, Status or Caller.
            7. Ensure the Actions panel displays an Action group is assigned to notify the appropriate personnel in your organization.
        Audit from Azure CLI
            az monitor activity-log alert list --subscription <subscription Id> --query '[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}'
        Audit From Powershell
            Look for Microsoft.Network/publicIPAddresses/write in the output
            Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object {$_.ConditionAllOf.Equal -match 'Microsoft.Network/publicIPAddresses/write'}|select-object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 1513498c-3091-461a-b321-e9b433218d28 - Name: 'Enable logging by category group for Public IP addresses (microsoft.network/publicipaddresses) to Log Analytics')"

  desc 'fix',
       'Remediate from Azure Portal
            1. Navigate to the Monitor blade.
            2. Select Alerts.
            3. Select Create.
            4. Select Alert rule.
            5. Choose a subscription.
            6. Select Apply.
            7. Select the Condition tab.
            8. Click See all signals.
            9. Select Create or Update Public Ip Address (Public Ip Address).
            10. Click Apply.
            11. Select the Actions tab.
            12. Click Select action groups to select an existing action group, or Create action group to create a new action group.
            13. Follow the prompts to choose or create an action group.
            14. Select the Details tab.
            15. Select a Resource group, provide an Alert rule name and an optional Alert rule description.
            16. Click Review + create.
            17. Click Create.
        Remediate from Azure CLI
            az monitor activity-log alert create --resource-group "<resource group name>" --condition category=Administrative and operationName=Microsoft.Network/publicIPAddresses/write and level=<verbose | information | warning | error | critical> --scope "/subscriptions/<subscription ID>" --name "<activity log rule name>" --subscription <subscription id> --action-group <action group ID>
        Remediate From Powershell
            Create the Conditions object.
                $conditions = @()
                $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -Equal Administrative -Field category
                $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -Equal Microsoft.Network/publicIPAddresses/write -Field operationName
                $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -Equal Verbose -Field level
            Retrieve the Action Group information and store in a variable, then create the Actions object.
                $actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -Name <action group name>
                $actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id
            Create the Scope object
                $scope = "/subscriptions/<subscription ID>"
            Create the Activity Log Alert Rule for Microsoft.Network/publicIPAddresses/write
                New-AzActivityLogAlert -Name "<activity log alert rule name>" -ResourceGroupName "<resource group name>" -Condition $conditions -Scope $scope -Location global -Action $actionObject -Subscription <subscription ID> -Enabled $true'

  impact 0.5
  tag nist: ['AU-3', 'AU-3(1)', 'AU-7', 'AU-12']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['8.5'] }]

  ref 'https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement'
  ref 'https://docs.microsoft.com/en-in/azure/azure-monitor/platform/alerts-activity-log'
  ref 'https://docs.microsoft.com/en-in/rest/api/monitor/activitylogalerts/createorupdate'
  ref 'https://docs.microsoft.com/en-in/rest/api/monitor/activitylogalerts/listbysubscriptionid'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation'

  subscription_id = input('subscription_id')

  activity_log_exists_create_update_public_ip_address_script = %(
            Get-AzActivityLogAlert -SubscriptionId "#{subscription_id}"|
            where-object {$_.ConditionAllOf.Equal -match "Microsoft.Network/publicIPAddresses/write"}|
            select-object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
    )

  pwsh_output = powershell(activity_log_exists_create_update_public_ip_address_script)
  describe 'Ensure that the subscription`s output for the activity log alert rule for Creating/Updating a Public IP address Rule' do
    subject { pwsh_output.stdout.strip }
    it 'is not empty' do
      expect(subject).not_to be_empty
    end
  end
end
