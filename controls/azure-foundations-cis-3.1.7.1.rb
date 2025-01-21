control 'azure-foundations-cis-3.1.7.1' do
    title "Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'"
    desc "Microsoft Defender for Azure Cosmos DB scans all incoming network requests for
        threats to your Azure Cosmos DB resources."

    desc 'rationale',
        "In scanning Azure Cosmos DB requests within a subscription, requests are compared to
        a heuristic list of potential security threats. These threats could be a result of a security
        breach within your services, thus scanning for them could prevent a potential security
        threat from being introduced."

    desc 'impact',
        "Enabling Microsoft Defender for Azure Cosmos DB requires enabling Microsoft
        Defender for your subscription. Both will incur additional charges."

    desc 'check',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud
        2. Select Environment Settings blade
        3. Click on the subscription name
        4. Select the Defender plans blade
        5. On the Database row click on Select types >
        6. Ensure the radio button next to Azure Cosmos DB is set to On.
        From Azure CLI
        Ensure the output of the below command is Standard
        az security pricing show -n CosmosDbs --query pricingTier
        From PowerShell
        Get-AzSecurityPricing -Name 'CosmosDbs' | Select-Object Name,PricingTier
        Ensure output of -PricingTier is Standard
        Page 130
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: adbe85b5-83e6-4350-ab58-bf3a4f736e5e - Name: 'Microsoft
        Defender for Azure Cosmos DB should be enabled'"

    desc 'fix',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Select Environment Settings blade.
        3. Click on the subscription name.
        4. Select the Defender plans blade.
        5. On the Database row click on Select types >.
        6. Set the radio button next to Azure Cosmos DB to On.
        7. Click Continue.
        8. Click Save.
        From Azure CLI
        Run the following command:
        az security pricing create -n 'CosmosDbs' --tier 'standard'
        From PowerShell
        Use the below command to enable Standard pricing tier for Azure Cosmos DB
        Set-AzSecurityPricing -Name 'CosmosDbs' -PricingTier 'Standard"

    impact 0.5
    tag nist: ['RA-5']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['7.5'] }]

    ref 'https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/'
    ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/enable-enhanced-security'
    ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview'
    ref 'https://docs.microsoft.com/en-us/security/benchmark/azure/baselines/cosmos-db-security-baseline'
    ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/quickstart-enable-database-protections'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities'

    describe 'benchmark' do
        skip 'configure'
    end
end