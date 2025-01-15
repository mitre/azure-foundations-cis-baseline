control 'azure-foundations-cis-2.1.7' do
    title "Ensure That Microsoft Defender for Storage Is Set To 'On'"
    desc "Turning on Microsoft Defender for Storage enables threat detection for Storage,
        providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft
        Defender for Cloud."

    desc 'rationale',
        "Enabling Microsoft Defender for Storage allows for greater defense-in-depth, with threat
        detection provided by the Microsoft Security Response Center (MSRC)."

    desc 'impact',
        "Turning on Microsoft Defender for Storage incurs an additional cost per resource."

    desc 'check',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Select Environment Settings blade.
        3. Click on the subscription name.
        4. Select the Defender plans blade.
        5. Ensure Status is set to On for Storage.
        From Azure CLI
        Ensure the output of the below command is Standard
        az security pricing show -n StorageAccounts
        From PowerShell
        Get-AzSecurityPricing -Name 'StorageAccounts' | Select-Object
        Name,PricingTier
        Ensure output for Name PricingTier is StorageAccounts StandardPage 133
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure. If referencing a printed copy, you can search
        Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 308fbb08-4ab8-4e67-9b29-592e93fb94fa - Name: 'Microsoft Defender
        for Storage (Classic) should be enabled'"

    desc 'fix',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Select Environment Settings blade.
        3. Click on the subscription name.
        4. Select the Defender plans blade.
        5. Set Status to On for Storage.
        6. Select Save.
        From Azure CLI
        Ensure the output of the below command is Standard
        az security pricing create -n StorageAccounts --tier 'standard'
        From PowerShell
        Set-AzSecurityPricing -Name 'StorageAccounts' -PricingTier 'Standard'"

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref "https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities"
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/list'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/update'
    ref 'https://docs.microsoft.com/en-us/powershell/module/az.security/get-azsecuritypricing'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities'

    describe 'benchmark' do
        skip 'configure'
    end
end