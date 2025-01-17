control 'azure-foundations-cis-2.1.1' do
    title "Ensure That Microsoft Defender for Servers Is Set to 'On'"
    desc "Turning on Microsoft Defender for Servers enables threat detection for Servers,
        providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft
        Defender for Cloud."

    desc 'rationale',
        "Enabling Microsoft Defender for Servers allows for greater defense-in-depth, with threat
        detection provided by the Microsoft Security Response Center (MSRC)."

    desc 'impact',
        "Turning on Microsoft Defender for Servers in Microsoft Defender for Cloud incurs an
        additional cost per resource."

    desc 'check',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud
        2. Select Environment Settings
        3. Click on the subscription name
        4. Select Defender plans
        5. Ensure Servers Status is set to On.
        From Azure CLI
        Run the following command:
        az security pricing show -n VirtualMachines --query pricingTier
        If the tenant is licensed and enabled, the output should indicate Standard
        From PowerShell
        Run the following command:
        Get-AzSecurityPricing -Name 'VirtualMachines' |Select-Object Name,PricingTier
        If the tenant is licensed and enabled, the -PricingTier parameter will indicate Standard
        Page 115
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 4da35fc9-c9e7-4960-aec9-797fe7d9051d - Name: 'Azure Defender
        for servers should be enabled'"

    desc 'fix',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud
        2. Select Environment Settings
        3. Click on the subscription name
        4. Select Defender plans
        5. Set Server Status to On
        6. Select Save
        From Azure CLI
        Run the following command:
        az security pricing create -n VirtualMachines --tier 'standard'
        From PowerShell
        Run the following command:
        Set-AzSecurityPricing -Name 'VirtualMachines' -PricingTier 'Standard'"

    impact 0.5
    tag nist: ['RA-5','SI-3']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['7.5','10.1'] }]

    ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/list'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/update'
    ref 'https://docs.microsoft.com/en-us/powershell/module/az.security/get-azsecuritypricing'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-security#es-1-use-endpoint-detection-and-response-edr'

    describe 'benchmark' do
        skip 'configure'
    end
end