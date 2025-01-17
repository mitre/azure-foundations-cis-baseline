control 'azure-foundations-cis-2.1.9' do
    title "Ensure That Microsoft Defender for Key Vault Is Set To 'On'"
    desc "Turning on Microsoft Defender for Key Vault enables threat detection for Key Vault,
        providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft
        Defender for Cloud."

    desc 'rationale',
        "Enabling Microsoft Defender for Key Vault allows for greater defense-in-depth, with
        threat detection provided by the Microsoft Security Response Center (MSRC)."

    desc 'impact',
        "Turning on Microsoft Defender for Key Vault incurs an additional cost per resource."

    desc 'check',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud
        2. Select Environment Settings blade
        3. Click on the subscription name
        4. Select the Defender plans blade
        5. Ensure Status is set to On for Key Vault.
        From Azure CLI
        Ensure the output of the below command is Standard
        az security pricing show -n 'KeyVaults' --query 'PricingTier'
        From PowerShell
        Get-AzSecurityPricing -Name 'KeyVaults' | Select-Object Name,PricingTier
        Ensure output for PricingTier is Standard
        Page 139
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 0e6763cc-5078-4e64-889d-ff4d9a839047 - Name: 'Azure Defender
        for Key Vault should be enabled'"

    desc 'fix',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud
        2. Select Environment Settings blade
        3. Click on the subscription name
        4. Select the Defender plans blade
        5. Select On under Status for Key Vault.
        6. Select Save.
        From Azure CLI
        Enable Standard pricing tier for Key Vault:
        az security pricing create -n 'KeyVaults' --tier 'Standard'
        From PowerShell
        Enable Standard pricing tier for Key Vault:
        Set-AzSecurityPricing -Name 'KeyVaults' -PricingTier 'Standard'"

    impact 0.5
    tag nist: ['RA-5']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['7.5'] }]

    ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/list'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/update'
    ref 'https://docs.microsoft.com/en-us/powershell/module/az.security/get-azsecuritypricing'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities'

    describe 'benchmark' do
        skip 'configure'
    end
end