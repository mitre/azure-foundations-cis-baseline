control 'azure-foundations-cis-3.1.7.2' do
  title "Ensure That Microsoft Defender for Open-Source Relational Databases Is Set To 'On'"
  desc "Turning on Microsoft Defender for Open-source relational databases enables threat
        detection for Open-source relational databases, providing threat intelligence, anomaly
        detection, and behavior analytics in the Microsoft Defender for Cloud."

  desc 'rationale',
       "Enabling Microsoft Defender for Open-source relational databases allows for greater
        defense-in-depth, with threat detection provided by the Microsoft Security Response
        Center (MSRC)"

  desc 'impact',
       "Turning on Microsoft Defender for Open-source relational databases incurs an
        additional cost per resource."

  desc 'check',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Select Environment Settings blade.
        3. Click on the subscription name.
        4. Select the Defender plans blade.
        5. Click Select types > in the row for Databases.
        6. Ensure the radio button next to Open-source relational databases is set to On.
        From Azure CLI
        Run the following command:
        az security pricing show -n OpenSourceRelationalDatabases --query pricingTier
        From PowerShell
        Get-AzSecurityPricing | Where-Object {$_.Name -eq
        'OpenSourceRelationalDatabases'} | Select-Object Name, PricingTier
        Ensure output for Name PricingTier is OpenSourceRelationalDatabases Standard
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 0a9fbe0d-c5c4-4da8-87d8-f4fd77338835 - Name: 'Azure Defender for
        open-source relational databases should be enabled'"

  desc 'fix',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Select Environment Settings blade.
        3. Click on the subscription name.
        4. Select the Defender plans blade.
        5. Click Select types > in the row for Databases.
        6. Set the radio button next to Open-source relational databases to On.
        7. Select Continue.
        8. Select Save.
        From Azure CLI
        Run the following command:
        az security pricing create -n 'OpenSourceRelationalDatabases' --tier
        'standard'
        From PowerShell
        Use the below command to enable Standard pricing tier for Open-source relational
        databases
        set-azsecuritypricing -name 'OpenSourceRelationalDatabases' -pricingtier
        'Standard'"

  impact 0.5
  tag nist: ['RA-5']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['7.5'] }]

  ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities'
  ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/update'
  ref 'https://docs.microsoft.com/en-us/powershell/module/az.security/get-azsecuritypricing'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-2-monitor-anomalies-and-threats-targeting-sensitive-data'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities'

  script = <<-EOH
        $ErrorActionPreference = "Stop"
        (Get-AzSecurityPricing -Name 'OpenSourceRelationalDatabases').PricingTier
  EOH

  pwsh_output = powershell(script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe 'Ensure That Microsoft Defender for Open-Source Relational Databases' do
    subject { pwsh_output.stdout.strip }
    it "is set to 'On'" do
      expect(subject).to eq('Standard')
    end
  end
end
