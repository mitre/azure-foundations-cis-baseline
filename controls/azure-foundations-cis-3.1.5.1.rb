control 'azure-foundations-cis-3.1.5.1' do
  title "Ensure That Microsoft Defender for Storage Is Set To 'On'"
  desc "Turning on Microsoft Defender for Storage enables threat detection for Storage,
        providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft
        Defender for Cloud."

  desc 'rationale',
       "Enabling Microsoft Defender for Storage allows for greater defense-in-depth, with threat
        detection provided by the Microsoft Security Response Center (MSRC)."

  desc 'impact',
       'Turning on Microsoft Defender for Storage incurs an additional cost per resource.'

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
        Ensure output for Name PricingTier is StorageAccounts Standard
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
  tag nist: ['RA-5']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['7.5'] }]

  ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities'
  ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/list'
  ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/update'
  ref 'https://docs.microsoft.com/en-us/powershell/module/az.security/get-azsecuritypricing'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities'

  script = <<-EOH
        $ErrorActionPreference = "Stop"
        (Get-AzSecurityPricing -Name 'StorageAccounts').PricingTier
  EOH

  pwsh_output = powershell(script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe 'Ensure That Microsoft Defender for Storage' do
    subject { pwsh_output.stdout.strip }
    it "is set to 'On'" do
      expect(subject).to cmp 'Standard'
    end
  end
end
