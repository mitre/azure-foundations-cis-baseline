control 'azure-foundations-cis-8.1' do
  title 'Ensure an Azure Bastion Host Exists'
  desc "The Azure Bastion service allows secure remote access to Azure Virtual Machines over the Internet without exposing remote access protocol ports and services directly to the Internet. The Azure Bastion service provides this access using TLS over 443/TCP, and subscribes to hardened configurations within an organization's Azure Active Directory service."

  desc 'rationale',
       'The Azure Bastion service allows organizations a more secure means of accessing Azure Virtual Machines over the Internet without assigning public IP addresses to those Virtual Machines. The Azure Bastion service provides Remote Desktop Protocol (RDP) and Secure Shell (SSH) access to Virtual Machines using TLS within a web browser, thus preventing organizations from opening up 3389/TCP and 22/TCP to the Internet on Azure Virtual Machines. Additional benefits of the Bastion service includes Multi-Factor Authentication, Conditional Access Policies, and any other hardening measures configured within Azure Active Directory using a central point of access.'

  desc 'impact',
       'The Azure Bastion service incurs additional costs and requires a specific virtual network configuration. The Standard tier offers additional configuration options compared to the Basic tier and may incur additional costs for those added features.'

  desc 'check',
       "Audit from Azure Portal
            1. Click on Bastions
            2. Ensure there is at least one Bastion host listed under the Name column
        Audit from Azure CLI
            Note: The Azure CLI network bastion module is in Preview as of this writing
                az network bastion list --subscription <subscription ID>
            Ensure the output of the above command is not empty.
        Audit From Powershell
            Retrieve the Bastion host(s) information for a specific Resource Group
                Get-AzBastion -ResourceGroupName <resource group name>
            Ensure the output of the above command is not empty"

  desc 'fix',
       %(Audit from Azure Portal
            1. Click on Bastions
            2. Select the Subscription
            3. Select the Resource group
            4. Type a Name for the new Bastion host
            5. Select a Region
            6. Choose Standard next to Tier
            7. Use the slider to set the Instance count
            8. Select the Virtual network or Create new
            9. Select the Subnet named AzureBastionSubnet. Create a Subnet named AzureBastionSubnet using a /26 CIDR range if it doesn't already exist.
            10. Selct the appropriate Public IP address option.
            11. If Create new is selected for the Public IP address option, provide a Public IP address name.
            12. If Use existing is selected for Public IP address option, select an IP address from Choose public IP address
            13. Click Next: Tags >
            14. Configure the appropriate Tags
            15. Click Next: Advanced >
            16. Select the appropriate Advanced options
            17. Click Next: Review + create >
            18. Click Create
        Audit from Azure CLI
            az network bastion create --location <location> --name <name of bastion host> --public-ip-address <public IP address name or ID> --resource-group <resource group name or ID> --vnet-name <virtual network containing subnet called "AzureBastionSubnet"> --scale-units <integer> --sku Standard [--disable-copy-paste true|false] [--enable-ip-connect true|false] [--enable-tunneling true|false]
        Audit From Powershell
            Create the appropriate Virtual network settings and Public IP Address settings.
                $subnetName = "AzureBastionSubnet"
                $subnet = New-AzVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix <IP address range in CIDR notation making sure to use a /26> $virtualNet = New-AzVirtualNetwork -Name <virtual network name> -ResourceGroupName <resource group name> -Location <location> -AddressPrefix <IP address range in CIDR notation> -Subnet $subnet
                $publicip = New-AzPublicIpAddress -ResourceGroupName <resource group name> -Name <public IP address name> -Location <location> -AllocationMethod Dynamic -Sku Standard
            Create the Azure Bastion service using the information within the created variables from above.
                New-AzBastion -ResourceGroupName <resource group name> -Name <bastion name> -PublicIpAddress $publicip -VirtualNetwork $virtualNet -Sku "Standard" -ScaleUnit <integer>)

  impact 0.5
  tag nist: ['CM-8(1)', 'CA-9', 'SC-7']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['12.1', '13.4'] }]

  ref 'https://learn.microsoft.com/en-us/azure/bastion/bastion-overview#sku'
  ref 'https://learn.microsoft.com/en-us/powershell/module/az.network/get-azbastion?view=azps-9.2.0'
  ref 'https://learn.microsoft.com/en-us/cli/azure/network/bastion?view=azure-cli-latest'

  subscription_id = input('subscription_id')
  puts(subscription_id)
  bastion_list = command('az network bastion list')
  puts('HERE')
  puts(bastion_list)
  puts(bastion_list.stderr)
  puts(bastion_list.stdout)
  puts('HERE 2')

  describe 'Ensure the bastions for resource groups' do
    subject { bastion_list.stdout.strip }
    it 'are not empty' do
      expect(subject).not_to eq('[]')
    end
  end
end
