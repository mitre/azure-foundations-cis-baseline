control 'azure-foundations-cis-7.7' do
  title 'Ensure that Public IP addresses are Evaluated on a Periodic Basis'
  desc 'Public IP Addresses provide tenant accounts with Internet connectivity for resources contained within the tenant. During the creation of certain resources in Azure, a Public IP Address may be created. All Public IP Addresses within the tenant should be periodically reviewed for accuracy and necessity.'

  desc 'rationale',
       'Public IP Addresses allocated to the tenant should be periodically reviewed for necessity. Public IP Addresses that are not intentionally assigned and controlled present a publicly facing vector for threat actors and significant risk to the tenant.'

  desc 'check',
       'Audit from Azure Portal
            1. Open the All Resources blade
            2. Click on Add Filter
            3. In the Add Filter window, select the following: Filter: Type Operator: Equals Value: Public IP address
            4. Click the Apply button
            5. For each Public IP address in the list, use Overview (or Properties) to review the "Associated to:" field and determine if the associated resource is still relevant to your tenant environment. If the associated resource is relevant, ensure that additional controls exist to mitigate risk (e.g. Firewalls, VPNs, Traffic Filtering, Virtual Gateway Appliances, Web Application Firewalls, etc.) on all subsequently attached resources.
        Audit from Azure CLI
            List all Public IP addresses:
                az network public-ip list
            For each Public IP address in the output, review the "name" property and determine if the associated resource is still relevant to your tenant environment. If the associated resource is relevant, ensure that additional controls exist to mitigate risk (e.g. Firewalls, VPNs, Traffic Filtering, Virtual Gateway Appliances, Web Application Firewalls, etc.) on all subsequently attached resources.'

  desc 'fix',
       "Remediation will vary significantly depending on your organization's security requirements for the resources attached to each individual Public IP address."

  impact 0.5
  tag nist: ['CM-8(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['12.1'] }]

  ref 'https://docs.microsoft.com/en-us/cli/azure/network/public-ip?view=azure-cli-latest'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security'

  relevant_public_ips = input('relevant_public_ip_addresses')
  azure_cli_ip_list = command('az network public-ip list --query "[].name" -o tsv').stdout.split("\n").reject(&:empty?)

  describe 'Ensure all public IPs present' do
    subject { azure_cli_ip_list.sort }
    it 'are relevant' do
      failure_message = "The IP lists do not match. Expected: #{relevant_public_ips.sort}, Got: #{subject}"
      expect(subject).to eq(relevant_public_ips.sort), failure_message
    end
  end
end
