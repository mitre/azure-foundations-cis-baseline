control 'azure-foundations-cis-3.1.3.3' do
    title "Ensure that 'Endpoint protection' component status is set to 'On' "
    desc "This integration setting enables Microsoft Defender for Endpoint (formerly 'Advanced
        Threat Protection' or 'ATP' or 'WDATP' - see additional info) to communicate with
        Microsoft Defender for Cloud.
        IMPORTANT: When enabling integration between DfE & DfC it needs to be taken into
        account that this will have some side effects that may be undesirable.
        1. For server 2019 & above if defender is installed (default for these server SKU's)
        this will trigger a deployment of the new unified agent and link to any of the
        extended configuration in the Defender portal.
        2. If the new unified agent is required for server SKU's of Win 2016 or Linux and
        lower there is additional integration that needs to be switched on and agents
        need to be aligned."

    desc 'rationale',
        "Microsoft Defender for Endpoint integration brings comprehensive Endpoint Detection
        and Response (EDR) capabilities within Microsoft Defender for Cloud. This integration
        helps to spot abnormalities, as well as detect and respond to advanced attacks on
        endpoints monitored by Microsoft Defender for Cloud.
        MDE works only with Standard Tier subscriptions."

    desc 'impact',
        "Endpoint protection requires licensing and is included in these plans:
        • Defender for Servers plan 1
        • Defender for Servers plan 2"

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Select Environment Settings blade
        4. Click on the subscription name
        5. Select the Integrations blade
        6. Ensure setting Allow Microsoft Defender for Endpoint to access my data is
        selected.
        From Azure CLI
        Ensure the output of the below command is True
        az account get-access-token --query
        '{subscription:subscription,accessToken:accessToken}' --out tsv | xargs -L1
        bash -c 'curl -X GET -H 'Authorization: Bearer $1' -H 'Content-Type:
        application/json'
        https://management.azure.com/subscriptions/<subscriptionID>/providers/Microso
        ft.Security/settings?api-version=2021-06-01' | jq '.|.value[] |
        select(.name=='WDATP')'|jq '.properties.enabled'
        From PowerShell
        Run the following commands to login and audit this check
        Connect-AzAccount
        Set-AzContext -Subscription <subscriptionID>
        Get-AzSecuritySetting | Select-Object name,enabled |where-object {$_.name -eq
        'WDATP'}
        PowerShell Output - Non-Compliant
        Name Enabled
        ---- -------
        WDATP False
        PowerShell Output - Compliant
        Name Enabled
        ---- -------
        WDATP True"

    desc 'fix',
       "From Azure Console
        1. From Azure Home select the Portal Menu.
        2. Go to Microsoft Defender for Cloud.
        3. Select Environment Settings blade.
        4. Select the subscription.
        5. Select Integrations.
        6. Check Allow Microsoft Defender for Endpoint to access my data.
        7. Select Save.
        From Azure CLI
        Use the below command to enable Standard pricing tier for Storage Accounts
        Page 174
        az account get-access-token --query
        '{subscription:subscription,accessToken:accessToken}' --out tsv | xargs -L1
        bash -c 'curl -X PUT -H 'Authorization: Bearer $1' -H 'Content-Type:
        application/json'
        https://management.azure.com/subscriptions/<subscriptionID>/providers/Microso
        ft.Security/settings/WDATP?api-version=2021-06-01 -d@'input.json''
        Where input.json contains the Request body json data as mentioned below.
        {
        'id':
        '/subscriptions/<Your_Subscription_Id>/providers/Microsoft.Security/settings/
        WDATP',
        'kind': 'DataExportSettings',
        'type': 'Microsoft.Security/settings',
        'properties': {
        'enabled': true
        }
        }"

    impact 0.5
    tag nist: ['RA-5','SI-3']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['7.5','10.1','13.2'] }]

    ref 'https://docs.microsoft.com/en-in/azure/defender-for-cloud/integration-defender-for-endpoint?tabs=windows'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/settings/list'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/settings/update'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-security#es-1-use-endpoint-detection-and-response-edr'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-security#es-2-use-modern-anti-malware-software'

    describe 'benchmark' do
        skip 'configure'
    end
end