control 'azure-foundations-cis-3.1.7.4' do
    title "Ensure That Microsoft Defender for SQL Servers on Machines Is Set To 'On'"
    desc "Turning on Microsoft Defender for SQL servers on machines enables threat detection
        for SQL servers on machines, providing threat intelligence, anomaly detection, and
        behavior analytics in Microsoft Defender for Cloud."

    desc 'rationale',
        "Enabling Microsoft Defender for SQL servers on machines allows for greater defense-
        in-depth, functionality for discovering and classifying sensitive data, surfacing and
        mitigating potential database vulnerabilities, and detecting anomalous activities that
        could indicate a threat to your database."

    desc 'impact',
        "Turning on Microsoft Defender for SQL servers on machines incurs an additional cost
        per resource."

    desc 'check',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Select Environment Settings blade.
        3. Click on the subscription name.
        4. Select the Defender plans blade.
        5. Click Select types > in the row for Databases.
        6. Ensure the radio button next to SQL servers on machines is set to On.
        From Azure CLI
        Ensure Defender for SQL is licensed with the following command:
        az security pricing show -n SqlServerVirtualMachines
        Ensure the 'PricingTier' is set to 'Standard'
        From PowerShell
        Run the following command:
        Get-AzSecurityPricing -Name 'SqlServerVirtualMachines' | Select-Object
        Name,PricingTier
        Ensure the 'PricingTier' is set to 'Standard'
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 6581d072-105e-4418-827f-bd446d56421b - Name: 'Azure Defender
        for SQL servers on machines should be enabled'
        • Policy ID: abfb4388-5bf4-4ad7-ba82-2cd2f41ceae9 - Name: 'Azure Defender for
        SQL should be enabled for unprotected Azure SQL servers'"

    desc 'fix',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Select Environment Settings blade.
        3. Click on the subscription name.
        4. Select the Defender plans blade.
        5. Click Select types > in the row for Databases.
        6. Set the radio button next to SQL servers on machines to On.
        7. Select Continue.
        8. Select Save.
        From Azure CLI
        Run the following command:
        az security pricing create -n SqlServerVirtualMachines --tier 'standard'
        From PowerShell
        Run the following command:
        Set-AzSecurityPricing -Name 'SqlServerVirtualMachines' -PricingTier
        'Standard'"

    impact 0.5
    tag nist: ['RA-5']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['7.5'] }]

    ref 'https://docs.microsoft.com/en-us/azure/security-center/defender-for-sql-usage'
    ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/update'
    ref 'https://docs.microsoft.com/en-us/powershell/module/az.security/get-azsecuritypricing'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-2-monitor-anomalies-and-threats-targeting-sensitive-data'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities'

    describe 'benchmark' do
        skip 'configure'
    end
end