control 'azure-foundations-cis-6.2.3' do
    title 'Ensure that Activity Log Alert exists for Create or Update Network Security Group'
    desc "Create an Activity Log Alert for the Create or Update Network Security Group event."

    desc 'rationale',
        "Monitoring for Create or Update Network Security Group events gives insight into network access changes and may reduce the time it takes to detect suspicious activity."

    desc 'check',
       "%(Audit from Azure Portal
            1. Navigate to the Monitor blade.
            2. Click on Alerts.
            3. In the Alerts window, click on Alert rules.
            4. Ensure an alert rule exists where the Condition column contains Operation name=Microsoft.Network/networkSecurityGroups/write.
            5. Click on the Alert Name associated with the previous step.
            6. Ensure the Condition panel displays the text Whenever the Activity Log has an event with Category='Administrative', Operation name='Create or Update Network Security Group' and does not filter on Level, Status or Caller.
            7. Ensure the Actions panel displays an Action group is assigned to notify the appropriate personnel in your organization.
        Audit from Azure CLI 
            az monitor activity-log alert list --subscription <subscription ID> --query '[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}'
            Look for Microsoft.Network/networkSecurityGroups/write in the output 
        Audit from PowerShell 
            Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object {$_.ConditionAllOf.Equal -match 'Microsoft.Network/networkSecurityGroups/write'}|select-object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: b954148f-4c11-4c38-8221-be76711e194a - Name: 'An activity log alert should exist for specific Administrative operations')"

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
            9. Select Create or Update Network Security Group (Network Security Group).
            10. Click Apply.
            11. Select the Actions tab.
            12. Click Select action groups to select an existing action group, or Create action group to create a new action group.
            13. Follow the prompts to choose or create an action group.
            14. Select the Details tab.
            15. Select a Resource group, provide an Alert rule name and an optional Alert rule description.
            16. Click Review + create.
            17. Click Create.
        Remediate from Azure CLI 
            az monitor activity-log alert create --resource-group "<resource group name>" --condition category=Administrative and operationName=Microsoft.Network/networkSecurityGroups/write and level=verbose --scope "/subscriptions/<subscription ID>" --name "<activity log rule name>" --subscription <subscription id> --action-group <action group ID>
        Remediate from PowerShell 
            Create the Conditions object. 
                $conditions = @() 
                $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -Equal Administrative -Field category 
                $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -Equal Microsoft.Network/networkSecurityGroups/write -Field operationName $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -Equal Verbose -Field level
            Retrieve the Action Group information and store in a variable, then create the Actions object. 
                $actionGroup = Get-AzActionGroup -ResourceGroupName <resource group name> -Name <action group name> 
                $actionObject = New-AzActivityLogAlertActionGroupObject -Id $actionGroup.Id
            Create the Scope object
                $scope = "/subscriptions/<subscription id>"
            Create the Activity Log Alert Rule for Microsoft.Network/networkSecurityGroups/write 
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

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end