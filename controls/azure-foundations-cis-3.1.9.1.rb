control 'azure-foundations-cis-3.1.9.1' do
  title "Ensure That Microsoft Defender for Resource Manager Is Set To 'On'"
  desc "Microsoft Defender for Resource Manager scans incoming administrative requests to
        change your infrastructure from both CLI and the Azure portal."

  desc 'rationale',
       "Scanning resource requests lets you be alerted every time there is suspicious activity in
        order to prevent a security threat from being introduced."

  desc 'impact',
       "Enabling Microsoft Defender for Resource Manager requires enabling Microsoft
        Defender for your subscription. Both will incur additional charges."

  desc 'check',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud
        2. Select Environment Settings blade
        3. Click on the subscription name
        4. Select the Defender plans blade
        5. Ensure Status is set to On for Resource Manager.
        From Azure CLI
        Ensure the output of the below command is Standard
        az security pricing show -n 'Arm' --query 'PricingTier'
        From Azure PowerShell
        Get-AzSecurityPricing -Name 'Arm' | Select-Object Name,PricingTier
        Ensure the output of PricingTier is Standard
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: c3d20c29-b36d-48fe-808b-99a87530ad99 - Name: 'Azure Defender
        for Resource Manager should be enabled'"

  desc 'fix',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Select Environment Settings blade.
        3. Click on the subscription name.
        4. Select the Defender plans blade.
        5. Select On under Status for Resource Manager.
        6. Select `Save.
        From Azure CLI
        Use the below command to enable Standard pricing tier for Defender for Resource
        Manager
        az security pricing create -n 'Arm' --tier 'Standard'
        From PowerShell
        Use the below command to enable Standard pricing tier for Defender for Resource
        Manager
        Set-AzSecurityPricing -Name 'Arm' -PricingTier 'Standard'"

  impact 0.5
  tag nist: ['AC-6(2)', 'AC-6(5)', 'RA-5']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['5.4', '7.5'] }]

  ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/enable-enhanced-security'
  ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/defender-for-resource-manager-introduction'
  ref 'https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/'
  ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities'

  script = <<-EOH
        (Get-AzSecurityPricing -Name 'Arm').PricingTier
  EOH

  pwsh_output = pwsh_azure_executor(script).run_script_in_azure

  describe 'Ensure That Microsoft Defender for Resource Manager' do
    subject { pwsh_output.stdout.strip }
    it "is set to 'On'" do
      expect(subject).to eq('Standard')
    end
  end
end
