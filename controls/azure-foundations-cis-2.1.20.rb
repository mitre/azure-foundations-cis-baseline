control 'azure-foundations-cis-2.1.20' do
    title "Ensure that Microsoft Defender for Cloud Apps integration with Microsoft Defender for Cloud is Selected"
    desc "This integration setting enables Microsoft Defender for Cloud Apps (formerly 'Microsoft
        Cloud App Security' or 'MCAS' - see additional info) to communicate with Microsoft
        Defender for Cloud."

    desc 'rationale',
        "Microsoft Defender for Cloud offers an additional layer of protection by using Azure
        Resource Manager events, which is considered to be the control plane for Azure. By
        analyzing the Azure Resource Manager records, Microsoft Defender for Cloud detects
        unusual or potentially harmful operations in the Azure subscription environment. Several
        of the preceding analytics are powered by Microsoft Defender for Cloud Apps. To
        benefit from these analytics, subscription must have a Cloud App Security license.
        Microsoft Defender for Cloud Apps works only with Standard Tier subscriptions."

    desc 'impact',
        "Microsoft Defender for Cloud Apps works with Standard pricing tier Subscription.
        Choosing the Standard pricing tier of Microsoft Defender for Cloud incurs an additional
        cost per resource."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Select Environment Settings blade
        4. Click on the subscription name
        5. Select the Integrations blade
        6. Ensure setting Allow Microsoft Defender for Cloud Apps to access my data
        is selected.
        From Azure CLI
        Ensure the output of the below command is True
        Page 169
        az account get-access-token --query
        '{subscription:subscription,accessToken:accessToken}' --out tsv | xargs -L1
        bash -c 'curl -X GET -H 'Authorization: Bearer $1' -H 'Content-Type:
        application/json'
        https://management.azure.com/subscriptions/<subscription_ID>/providers/Micros
        oft.Security/settings?api-version=2021-06-01' | jq '.|.value[] |
        select(.name=='MCAS')'|jq '.properties.enabled'
        From PowerShell
        Run the following series of commands to audit this configuration
        Get-AzAccount
        Set-AzContext -Subscription <subscription ID>
        Get-AzSecuritySetting | Select-Object name,enabled |where-object {$_.name -eq
        'MCAS'}
        PowerShell Output - Non-Compliant
        Name Enabled
        ---- -------
        MCAS False
        PowerShell Output - Compliant
        Name Enabled
        ---- -------
        MCAS True"

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu.
        2. Select Microsoft Defender for Cloud.
        3. Select Environment Settings blade.
        4. Select the subscription.
        5. Select Integrations.
        6. Check Allow Microsoft Defender for Cloud Apps to access my data.
        7. Select Save.
        From Azure CLI
        Use the below command to enable Standard pricing tier for Storage Accounts
        az account get-access-token --query
        '{subscription:subscription,accessToken:accessToken}' --out tsv | xargs -L1
        bash -c 'curl -X PUT -H 'Authorization: Bearer $1' -H 'Content-Type:
        application/json'
        https://management.azure.com/subscriptions/<subscription_ID>/providers/Micros
        oft.Security/settings/MCAS?api-version=2021-06-01 -d@'input.json''
        Where input.json contains the Request body json data as mentioned below.
        Page 170
        'id':
        '/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/settings/
        MCAS',
        'kind': 'DataExportSetting',
        'type': 'Microsoft.Security/settings',
        'properties': {
        'enabled': true
        Default Value:
        With Cloud App Security license, these alerts are enabled by default"

    impact 0.5
    tag nist: ['RA-5','SC-7(8)','SA-15']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['7.5','7.6','13.10','16.11'] }]

    ref 'https://docs.microsoft.com/en-in/azure/security-center/security-center-alerts-service-layer#azure-management-layer-azure-resource-manager-preview'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/settings/list'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/settings/update'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-9-secure-user-access-to--existing-applications'

    describe 'benchmark' do
        skip 'configure'
    end
end