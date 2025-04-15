control 'azure-foundations-cis-7.2' do
  title 'Ensure that SSH access from the Internet is evaluated and restricted'
  desc 'Network security groups should be periodically evaluated for port misconfigurations. Where certain ports and protocols may be exposed to the Internet, they should be evaluated for necessity and restricted wherever they are not explicitly required.'

  desc 'rationale',
       'The potential security problem with using SSH over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on the Azure Virtual Network or even attack networked devices outside of Azure.'

  desc 'check',
       %(Audit from Azure Portal
            1. Open the Networking blade for the specific Virtual machine in Azure portal
            2. Verify that the INBOUND PORT RULES does not have a rule for SSH such as
                o port = 22,
                o protocol = TCP OR ANY,
                o Source = Any OR Internet
        Audit from Azure CLI
            List Network security groups with corresponding non-default Security rules:
                az network nsg list --query [*].[name,securityRules]
            Ensure that none of the NSGs have security rule as below
                "access" : "Allow"
                "destinationPortRange" : "22" or "*" or "[port range containing 22]"
                "direction" : "Inbound"
                "protocol" : "TCP" or "*" "sourceAddressPrefix" : "*" or "0.0.0.0" or "<nw>/0" or "/0" or "internet" or "any"
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 22730e10-96f6-4aac-ad84-9383d35b5917 - Name: 'Management ports should be closed on your virtual machines')

  desc 'fix',
       "Where SSH is not explicitly required and narrowly configured for resources attached to the Network Security Group, Internet-level access to your Azure resources should be restricted or eliminated. For internal access to relevant resources, configure an encrypted network tunnel such as:
            ExpressRoute
            Site-to-site VPN
            Point-to-site VPN"

  impact 0.5
  tag nist: ['CA-9', 'SC-7', 'SC-7(5)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['4.4', '4.5', '13.4'] }]

  ref 'https://docs.microsoft.com/en-us/azure/security/azure-security-network-security-best-practices#disable-rdpssh-access-to-azure-virtual-machines'
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

  # Collect NSGs with at least one insecure SSH rule
  nsgs_with_insecure_rules = query_results_json.select do |nsg|
    nsg_name = nsg[0]
    security_rules = nsg[1]

    security_rules.any? do |rule|
      rule['access'] == 'Allow' &&
        rule['direction'] == 'Inbound' &&
        (rule['protocol'] == 'TCP' || rule['protocol'] == '*') &&
        (
          rule['destinationPortRange'] == '22' ||
          rule['destinationPortRange'] == '*' ||
          (rule['destinationPortRange'] =~ /22/)
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
  end

  describe 'Network Security Groups (NSGs)' do
    it 'should not have any unrestricted SSH rules' do
      failure_message = nsgs_with_insecure_rules.map do |nsg|
        nsg_name = nsg[0]
        security_rules = nsg[1]

        insecure_rules = security_rules.select do |rule|
          rule['access'] == 'Allow' &&
            rule['direction'] == 'Inbound' &&
            ['TCP', '*'].include?(rule['protocol']) &&
            (
              ['22', '*'].include?(rule['destinationPortRange']) || rule['destinationPortRange'] =~ /22/
            ) &&
            (
              ['*', '0.0.0.0', '/0', 'internet', 'any'].include?(rule['sourceAddressPrefix'].downcase) || rule['sourceAddressPrefix'] =~ %r{/0}
            )
        end

        # Format the failure message for this NSG
        rules_messages = insecure_rules.map do |rule|
          <<~RULE_DETAILS
            Rule '#{rule['name']}' failed due to matched insecure configuration:
            - Access: #{rule['access']} (Matched Condition: #{'Access is "Allow"' if ['Allow'].include?(rule['access'])})
            - Direction: #{rule['direction']} (Matched Condition: #{'Direction is "Inbound"' if ['Inbound'].include?(rule['direction'])})
            - Protocol: #{rule['protocol']} (Matched Condition: #{'Protocol is "TCP" or "*"' if ['TCP', '*'].include?(rule['protocol'])})
            - Destination Port Range: #{rule['destinationPortRange']} (Matched Condition: #{'Destination Port Range is "22", "*", or matches /22/' if ['22', '*'].include?(rule['destinationPortRange']) || rule['destinationPortRange'] =~ /22/})
            - Source Address Prefix: #{rule['sourceAddressPrefix']} (Matched Condition: #{'Source Address Prefix is "*", "0.0.0.0", "/0", matches /0, "internet", or "any"' if ['*', '0.0.0.0', '/0', 'internet', 'any'].include?(rule['sourceAddressPrefix'].downcase) || rule['sourceAddressPrefix'] =~ %r{/0}})

          RULE_DETAILS
        end.join("\n")
        "NSG '#{nsg_name}' has the following insecure rules:\n#{rules_messages}"
      end.join("\n\n")
      expect(nsgs_with_insecure_rules).to be_empty, failure_message
    end
  end
end
