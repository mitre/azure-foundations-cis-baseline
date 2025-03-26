control 'azure-foundations-cis-7.3' do
  title 'Ensure that UDP access from the Internet is evaluated and restricted'
  desc 'Network security groups should be periodically evaluated for port misconfigurations. Where certain ports and protocols may be exposed to the Internet, they should be evaluated for necessity and restricted wherever they are not explicitly required.'

  desc 'rationale',
       'The potential security problem with broadly exposing UDP services over the Internet is that attackers can use DDoS amplification techniques to reflect spoofed UDP traffic from Azure Virtual Machines. The most common types of these attacks use exposed DNS, NTP, SSDP, SNMP, CLDAP and other UDP-based services as amplification sources for disrupting services of other machines on the Azure Virtual Network or even attack networked devices outside of Azure.'

  desc 'check',
       'Audit from Azure Portal
            1. Open the Networking blade for the specific Virtual machine in Azure portal
            2. Verify that the INBOUND PORT RULES does not have a rule for UDP such as
                • protocol = UDP,
                • Source = Any OR Internet
        Audit from Azure CLI
            List Network security groups with corresponding non-default Security rules:
                az network nsg list --query [*].[name,securityRules]
            Ensure that none of the NSGs have security rule as below
                "access" : "Allow"
                "destinationPortRange" : "*" or "[port range containing 53, 123, 161, 389, 1900, or other vulnerable UDP-based services]"
                "direction" : "Inbound"
                "protocol" : "UDP"
                "sourceAddressPrefix" : "*" or "0.0.0.0" or "<nw>/0" or "/0" or "internet" or "any"'

  desc 'fix',
       "Where UDP is not explicitly required and narrowly configured for resources attached to the Network Security Group, Internet-level access to your Azure resources should be restricted or eliminated. For internal access to relevant resources, configure an encrypted network tunnel such as:
            ExpressRoute
            Site-to-site VPN
            Point-to-site VPN"

  impact 0.5
  tag nist: ['CA-9', 'SC-7', 'SC-7(5)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['4.4', '4.5', '13.4'] }]

  ref 'https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices#secure-your-critical-azure-service-resources-to-only-your-virtual-networks'
  ref 'https://docs.microsoft.com/en-us/azure/security/fundamentals/ddos-best-practices'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-1-establish-network-segmentation-boundaries'
  ref 'https://docs.microsoft.com/en-us/azure/expressroute/'
  ref 'https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-site-to-site-resource-manager-portal'
  ref 'https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-resource-manager-portal'

  nsg_script = 'az network nsg list'
  nsg_output = powershell(nsg_script).stdout.strip
  all_nsgs = json(content: nsg_output).params

  only_if('N/A - No Network Security Groups found', impact: 0) do
    case all_nsgs
    when Array
      !all_nsgs.empty?
    when Hash
      !all_nsgs.empty?
    else
      false
    end
  end

  query = command('az network nsg list --query "[*].[name,securityRules]" -o json').stdout
  query_results_json = JSON.parse(query) unless query.empty?
  query_results_json.each do |nsg|
    nsg_name = nsg[0]
    security_rules = nsg[1]
    describe "NSG: #{nsg_name}" do
      it 'should not return any unrestricted UDP rule' do
        insecure_rules = security_rules.select do |rule|
          rule['access'] == 'Allow' &&
            rule['direction'] == 'Inbound' &&
            rule['protocol'] == 'UDP' &&
            (
              rule['destinationPortRange'] == '*' ||
              (rule['destinationPortRange'] =~ /53|123|161|389|1900/)
            ) &&
            (
              rule['sourceAddressPrefix'] == '*' ||
              rule['sourceAddressPrefix'] == '0.0.0.0' ||
              rule['sourceAddressPrefix'] == '/0' ||
              rule['sourceAddressPrefix'] =~ %r{/0} ||
              rule['sourceAddressPrefix'].downcase == 'internet' ||
              rule['sourceAddressPrefix'].downcase == 'any'
            )
        end
        failure_message = "Check #{nsg_name} NSG's UDP access, direction, protocol, destinationPortRange, and sourceAddressPrefix fields for proper configurations"
        expect(insecure_rules).to be_empty, failure_message
      end
    end
  end
end
