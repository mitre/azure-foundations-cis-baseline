control 'azure-foundations-cis-3.1.8.1' do
  title "Ensure That Microsoft Defender for Key Vault Is Set To 'On'"
  desc "Turning on Microsoft Defender for Key Vault enables threat detection for Key Vault,
        providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft
        Defender for Cloud."

  desc 'rationale',
       "Enabling Microsoft Defender for Key Vault allows for greater defense-in-depth, with
        threat detection provided by the Microsoft Security Response Center (MSRC)."

  desc 'impact',
       'Turning on Microsoft Defender for Key Vault incurs an additional cost per resource.'

  desc 'check',
       "Audit from Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Under Management, select Environment Settings.
        3. Click on the subscription name.
        4. Select the Defender plans blade.
        5. Ensure Status is set to On for Key Vault.
        Audit from Azure CLI
        Ensure the output of the below command is Standard
        az security pricing show -n 'KeyVaults' --query 'pricingTier'
        Audit from PowerShell
        Get-AzSecurityPricing -Name 'KeyVaults' | Select-Object Name,PricingTier
        Ensure output for PricingTier is Standard
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 0e6763cc-5078-4e64-889d-ff4d9a839047 - Name: 'Azure Defender
        for Key Vault should be enabled'"

  desc 'fix',
       "Remediate from Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Under Management, select Environment Settings.
        3. Click on the subscription name.
        4. Select the Defender plans blade.
        5. Select On under Status for Key Vault.
        6. Select Save.
        Remediate from Azure CLI
        Enable Standard pricing tier for Key Vault:
        az security pricing create -n 'KeyVaults' --tier 'Standard'
        Remediate from PowerShell
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

  script = <<-EOH
        (Get-AzSecurityPricing -Name 'KeyVaults').PricingTier
  EOH

  pwsh_output = pwsh_azure_executor(script).run_script_in_azure

  describe 'Ensure That Microsoft Defender for Key Vault' do
    subject { pwsh_output.stdout.strip }
    it "is set to 'On'" do
      expect(subject).to eq('Standard')
    end
  end
end
