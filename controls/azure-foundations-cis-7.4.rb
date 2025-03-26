control 'azure-foundations-cis-7.4' do
  title 'Ensure that HTTP(S) access from the Internet is evaluated and restricted'
  desc 'Network security groups should be periodically evaluated for port misconfigurations. Where certain ports and protocols may be exposed to the Internet, they should be evaluated for necessity and restricted wherever they are not explicitly required and narrowly configured.'

  desc 'rationale',
       'The potential security problem with using HTTP(S) over the Internet is that attackers can use various brute force techniques to gain access to Azure resources. Once the attackers gain access, they can use the resource as a launch point for compromising other resources within the Azure tenant.'

  desc 'check',
       'Audit from Azure Portal
            1. For each VM, open the Networking blade
            2. Verify that the INBOUND PORT RULES does not have a rule for HTTP(S) such as
                o port = 80/ 443,
                o protocol = TCP,
                o Source = Any OR Internet
        Audit from Azure CLI
            List Network security groups with corresponding non-default Security rules:
                az network nsg list --query [*].[name,securityRules]
            Ensure that none of the NSGs have security rule as below
                "access" : "Allow"
                "destinationPortRange" : "80/443" or "*" or "[port range containing 80/443]"
                "direction" : "Inbound"
                "protocol" : "TCP"
                "sourceAddressPrefix" : "*" or "0.0.0.0" or "<nw>/0" or "/0" or "internet" or "any"'

  desc 'fix',
       %(Remediate from Azure Portal
            1. Go to Virtual machines.
            2. For each VM, open the Networking blade.
            3. Click on Inbound port rules.
            4. Delete the rule with:
                o Port = 80/443 OR [port range containing 80/443]
                o Protocol = TCP OR Any
                o Source = Any (*) OR IP Addresses(0.0.0.0/0) OR Service Tag(Internet)
                o Action = Allow
        Remediate from Azure CLI
            Run below command to list network security groups:
                az network nsg list --subscription <subscription-id> --output table
            1. For each network security group, run below command to list the rules associated with the specified port:
                az network nsg rule list --resource-group <resource-group> --nsg-name <nsg-name> --query "[?destinationPortRange=='80 or 443']"
            2. Run the below command to delete the rule with:
                o Port = 80/443 OR [port range containing 80/443]
                o Protocol = TCP OR "*"
                o Source = Any (*) OR IP Addresses(0.0.0.0/0) OR Service Tag(Internet)
                o Action = Allow

                az network nsg rule delete --resource-group <resource-group> --nsg-name <nsg-name> --name <rule-name>)

  impact 0.5
  tag nist: ['CA-9', 'SC-7', 'SC-7(5)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['4.4', '4.5', '13.4'] }]

  ref 'https://docs.microsoft.com/en-us/azure/expressroute/'
  ref 'https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-site-to-site-resource-manager-portal'
  ref 'https://docs.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-resource-manager-portal'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-1-establish-network-segmentation-boundaries'

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
    nsg_name = nsg[0] # NSG name
    security_rules = nsg[1]
    describe "NSG: #{nsg_name}" do
      it 'should not return any unrestricted HTTP/HTTPS rule' do
        insecure_rules = security_rules.select do |rule|
          rule['access'] == 'Allow' &&
            rule['direction'] == 'Inbound' &&
            rule['protocol'] == 'TCP' &&
            (
              rule['destinationPortRange'] == '80' ||
              rule['destinationPortRange'] == '443' ||
              rule['destinationPortRange'] == '*' ||
              (rule['destinationPortRange'] =~ /80|443/) # Port range containing 80 or 443
            ) &&
            (
              rule['sourceAddressPrefix'] == '*' ||
              rule['sourceAddressPrefix'] == '0.0.0.0' ||
              rule['sourceAddressPrefix'] == '/0' ||
              rule['sourceAddressPrefix'] =~ %r{/0} || # CIDR ranges ending in /0
              rule['sourceAddressPrefix'].downcase == 'internet' ||
              rule['sourceAddressPrefix'].downcase == 'any'
            )
        end
        failure_message = "Check #{nsg_name} NSG's HTTP/HTTPS access, direction, protocol, destinationPortRange, and sourceAddressPrefix fields for proper configurations"
        expect(insecure_rules).to be_empty, failure_message # Ensure no insecure rules exist
      end
    end
  end
end
