control 'azure-foundations-cis-3.1.6.1' do
  title "Ensure That Microsoft Defender for App Services Is Set To 'On'"
  desc "Turning on Microsoft Defender for App Service enables threat detection for App Service,
        providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft
        Defender for Cloud."

  desc 'rationale',
       "Enabling Microsoft Defender for App Service allows for greater defense-in-depth, with
        threat detection provided by the Microsoft Security Response Center (MSRC)."

  desc 'impact',
       'Turning on Microsoft Defender for App Service incurs an additional cost per resource.'

  desc 'check',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud
        2. Select Environment Settings
        3. Click on the subscription name
        4. Select Defender plans
        5. Ensure Status is On for App Service
        From Azure CLI
        Run the following command:
        az security pricing show -n AppServices
        Ensure -PricingTier is set to Standard
        From PowerShell
        Run the following command:
        Get-AzSecurityPricing -Name 'AppServices' |Select-Object Name,PricingTier
        Ensure the -PricingTier is set to Standard
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 2913021d-f2fd-4f3d-b958-22354e2bdbcb - Name: 'Azure Defender for
        App Service should be enabled'"

  desc 'fix',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud
        2. Select Environment Settings
        3. Click on the subscription name
        4. Select Defender plans
        5. Set App Service Status to On
        6. Select Save
        From Azure CLI
        Run the following command:
        az security pricing create -n Appservices --tier 'standard'
        From PowerShell
        Run the following command:
        Set-AzSecurityPricing -Name 'AppServices' -PricingTier 'Standard'"

  impact 0.5
  tag nist: ['RA-5', 'RA-5']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['7.5', '7.6'] }]

  ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities'
  ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/list'
  ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/update'
  ref 'https://docs.microsoft.com/en-us/powershell/module/az.security/get-azsecuritypricing'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities'

  script = <<-EOH
        (Get-AzSecurityPricing -Name 'AppServices').PricingTier
  EOH

  pwsh_output = pwsh_azure_executor(script).run_script_in_azure

  describe 'Ensure That Microsoft Defender for App Services' do
    subject { pwsh_output.stdout.strip }
    it "is set to 'On'" do
      expect(subject).to eq('Standard')
    end
  end
end
