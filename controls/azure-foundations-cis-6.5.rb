control 'azure-foundations-cis-6.5' do
  title 'Ensure that SKU Basic/Consumption is not used on artifacts that need to be monitored (Particularly for Production Workloads)'
  desc 'The use of Basic or Free SKUs in Azure whilst cost effective have significant limitations in terms of what can be monitored and what support can be realized from Microsoft. Typically, these SKU’s do not have a service SLA and Microsoft may refuse to provide support for them. Consequently Basic/Free SKUs should never be used for production workloads.'

  desc 'rationale',
       "Typically, production workloads need to be monitored and should have an SLA with Microsoft, using Basic SKUs for any deployed product will mean that that these capabilities do not exist.
        The following resource types should use standard SKUs as a minimum.
            • Public IP Addresses
            • Network Load Balancers
            • REDIS Cache
            • SQL PaaS Databases
            • VPN Gateways"

  desc 'impact',
       "The impact of enforcing Standard SKU's is twofold
            1. There will be a cost increase
            2. The monitoring and service level agreements will be available and will support the production service.
        All resources should be either tagged or in separate Management Groups/Subscriptions"

  desc 'check',
       "%(This needs to be audited by Azure Policy (one for each resource type) and denied for each artifact that is production.
       Audit from Azure Portal
            1. Open Azure Resource Graph Explorer
            2. Click New query
            3. Paste the following into the query window: Resources | where sku contains 'Basic' or sku contains 'consumption' | order by type
            4. Click Run query then evaluate the results in the results window.
        Audit from Azure CLI
            az graph query -q 'Resources | sku contains 'Basic' or sku contains 'consumption' | order by type'
        Audit From Powershell
            Get-AzResource | ?{ $_.Sku -EQ 'Basic'})"

  desc 'fix',
       "Each artifact has its own process for upgrading from basic to standard SKU's and this should be followed if required."

  impact 0.5
  tag nist: ['SA-22']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['2.2'] }]

  ref 'https://azure.microsoft.com/en-us/support/plans'
  ref 'https://azure.microsoft.com/en-us/support/plans/response/'

  resource_script = 'Get-AzResource | ConvertTo-Json'
  resource_output = powershell(resource_script).stdout.strip
  all_resources = json(content: resource_output).params

  only_if('N/A - No Resources found', impact: 0) do
    case all_resources
    when Array
      !all_resources.empty?
    when Hash
      !all_resources.empty?
    else
      false
    end
  end

  script = <<-EOH
     $ErrorActionPreference = "Stop"
     Get-AzResource | Where-Object { $_.Sku -eq 'Basic' }
  EOH

  pwsh_output = powershell(script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe 'Ensure the number of production artifacts with SKU Basic/Consumption' do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following resources have SKU Basic: #{pwsh_output.stdout}"
        expect(subject).to be_empty, failure_message
      end
  end
end
