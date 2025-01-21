control 'azure-foundations-cis-3.1.16' do
    title "[LEGACY] Ensure That Microsoft Defender for DNS Is Set To 'On'"
    desc "NOTE: As of August 1, customers with an existing subscription to Defender for DNS
        can continue to use the service, but new subscribers will receive alerts about suspicious
        DNS activity as part of Defender for Servers P2.]
        Microsoft Defender for DNS scans all network traffic exiting from within a subscription."

    desc 'rationale',
        "DNS lookups within a subscription are scanned and compared to a dynamic list of
        websites that might be potential security threats. These threats could be a result of a
        security breach within your services, thus scanning for them could prevent a potential
        security threat from being introduced."

    desc 'impact',
        "Enabling Microsoft Defender for DNS requires enabling Microsoft Defender for your
        subscription. Both will incur additional charges, with Defender for DNS being a small
        amount per million queries."

    desc 'check',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud
        2. Select Environment Settings blade
        3. Click on the subscription name
        4. Select the Defender plans blade
        5. Ensure Status is set to On for DNS.
        From Azure CLI
        Ensure the output of the below command is Standard
        az security pricing show -n 'DNS' --query 'PricingTier'
        From PowerShell
        Get-AzSecurityPricing --Name 'DNS' | Select-Object Name,PricingTier
        Ensure output of PricingTier is Standard
        Page 142
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: bdc59948-5574-49b3-bb91-76b7c986428d - Name: 'Azure Defender
        for DNS should be enabled'"

    desc 'fix',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Select Environment Settings blade.
        3. Click on the subscription name.
        4. Select the Defender plans blade.
        5. Select On under Status for DNS.
        6. Select Save.
        From Powershell
        Enable Standard pricing tier for DNS:
        az security pricing create -n 'DNS' --tier 'Standard'
        From PowerShell
        Enable Standard pricing tier for DNS:
        Set-AzSecurityPricing -Name 'DNS' -PricingTier 'Standard'"

    impact 0.5
    tag nist: ['SC-20','SC-21','SC-22','RA-5','SI-4','SI-4(4)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['4.9','7.5','13.6'] }]

    ref 'https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/'
    ref 'https://docs.microsoft.com/en-us/security/benchmark/azure/baselines/dns-security-baseline'
    ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/defender-for-dns-alerts'
    ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/enable-enhanced-security'
    ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview'
    ref 'https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-network-security#ns-10-ensure-domain-name-system-dns-security'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities'

    describe 'benchmark' do
        skip 'configure'
    end
end