control 'azure-foundations-cis-2.1.3' do
    title "Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'"
    desc "Turning on Microsoft Defender for Azure SQL Databases enables threat detection for
        Managed Instance Azure SQL databases, providing threat intelligence, anomaly
        detection, and behavior analytics in Microsoft Defender for Cloud."

    desc 'rationale',
        "Enabling Microsoft Defender for Azure SQL Databases allows for greater defense-in-
        depth, includes functionality for discovering and classifying sensitive data, surfacing and
        mitigating potential database vulnerabilities, and detecting anomalous activities that
        could indicate a threat to your database."

    desc 'impact',
        "Turning on Microsoft Defender for Azure SQL Databases incurs an additional cost per
        resource."

    desc 'check',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Select Environment Settings blade.
        3. Click on the subscription name.
        4. Select the Defender plans blade.
        5. Click Select types > in the row for Databases.
        6. Ensure the radio button next to Azure SQL Databases is set to On.
        From Azure CLI
        Run the following command:
        az security pricing show -n SqlServers
        Ensure -PricingTier is set to Standard
        From PowerShell
        Run the following command:
        Get-AzSecurityPricing -Name 'SqlServers' | Select-Object Name,PricingTier
        Ensure the -PricingTier is set to Standard
        Page 121
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 7fe3b40f-802b-4cdd-8bd4-fd799c948cc2 - Name: 'Azure Defender for
        Azure SQL Database servers should be enabled'
        • Policy ID: abfb7388-5bf4-4ad7-ba99-2cd2f41cebb9 - Name: 'Azure Defender for
        SQL should be enabled for unprotected SQL Managed Instances'"

    desc 'fix',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Select Environment Settings blade.
        3. Click on the subscription name.
        4. Select the Defender plans blade.
        5. Click Select types > in the row for Databases.
        6. Set the radio button next to Azure SQL Databases to On.
        7. Select Continue.
        8. Select Save.
        From Azure CLI
        Run the following command:
        az security pricing create -n SqlServers --tier 'standard'
        From PowerShell
        Run the following command:
        Set-AzSecurityPricing -Name 'SqlServers' -PricingTier 'Standard'"

    impact 0.5
    tag nist: ['check NIST SP 800-53, Revision 5']
    tag severity: 'low, medium, or high '
    tag cis_controls: [{ '8.1' => ['check cis controls navigator'] }]

    ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/list'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/update'
    ref 'https://docs.microsoft.com/en-us/powershell/module/az.security/get-azsecuritypricing'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-2-monitor-anomalies-and-threats-targeting-sensitive-data'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities'

    describe 'benchmark' do
        skip 'configure'
    end
end