control 'azure-foundations-cis-8.5' do
  title "Ensure that 'Disk Network Access' is NOT set to 'Enable public access from all networks'"
  desc 'Virtual Machine Disks and snapshots can be configured to allow access from different network resources.'

  desc 'rationale',
       "The setting 'Enable public access from all networks' is, in many cases, an overly permissive setting on Virtual Machine Disks that presents atypical attack, data infiltration, and data exfiltration vectors. If a disk to network connection is required, the preferred setting is to 'Disable public access and enable private access."

  desc 'impact',
       "The setting 'Disable public access and enable private access' will require configuring a private link (URL in references below).
        The setting 'Disable public and private access' is most secure and preferred where disk network access is not needed."

  desc 'check',
       %(
       Audit from Azure Portal
            Part A. Select the Virtual Machine to Evaluate
                1. Using the search bar, search for and open the Virtual Machines service.
                2. Click on the name of the Virtual Machine to be audited.
            Part B. Evaluate each Virtual Machine Disk individually
                1. From the selected Virtual Machine resource window, expand the Settings menu item and click Disks.
                2. For each disk, click the name of the disk to open the disk resource window.
                3. From the selected Disk resource window, expand the Settings menu item, and click Networking.
            Ensure that Network access is NOT set to Enable public access from all networks.
            Repeat Part B for each Disk attached to a VM.
            Repeat Parts A and B to evaluate all Disks in all VMs.
        Audit from PowerShell
            For each managed disk, run the following PowerShell command:
                Get-AzDisk -ResourceGroupName ‘<resource group name>’ -DiskName ‘<disk name>’
            Ensure the PublicNetworkAccess setting is Disabled and the NetworkAccessPolicy is set to AllowPrivate or DenyAll.
        Audit from Azure CLI
            For each managed disk, run the following command:
                az disk show --disk-name ‘<disk name>’ --resource-group ‘<resource group name>’
            Ensure the publicNetworkAccess setting is set to Disabled and the networkAccessPolicy setting is set to AllowPrivate or DenyAll.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 8405fdab-1faf-48aa-b702-999c9c172094 - Name: 'Managed disks should disable public network access')

  desc 'fix',
       "Remediate from Azure Portal
            Part A. Select the Virtual Machine to Remediate
                1. Using the search bar, search for and open the Virtual Machines service.
                2. Click on the name of the Virtual Machine to be remediated.
            Part B. Remediate each Virtual Machine Disk individually
                1. From the selected Virtual Machine resource window, expand the Settings menu item and click Disks.
                2. For each disk, click the name of the disk to open the disk resource window.
                3. From the selected Disk resource window, expand the Settings menu item, and click Networking.
            Under Network access, select the radio button for either:
                • Disable public access and enable private access
                • Disable public and private access
            Repeat Part B for each Disk attached to a VM.
            Repeat Parts A and B to remediate all Disks in all VMs.
        Remediate from PowerShell
            To disable PublicNetworkAccess and to set a DenyAll setting for the disk's NetworkAccessPolicy for each managed disk, run the following command:
                $disk = Get-AzDisk -ResourceGroupName ‘<resource group name>’ -DiskName ‘<disk name>’
                $disk.NetworkAccessPolicy = 'DenyAll'
                $disk.PublicNetworkAccess = 'Disabled'
                Update-AzDisk -ResourceGroup '<resource group name> -DiskName $disk.Name -Disk $disk
            To disable PublicNetworkAccess and to set an AllowPrivate setting for the disk's NetworkAccessPolicy for each managed disk, run the following command:
                $disk = Get-AzDisk -ResourceGroupName ‘<resource group name>’ -DiskName ‘<disk name>’
                $disk.NetworkAccessPolicy = 'AllowPrivate' $disk.PublicNetworkAccess = 'Disabled'
                $disk.DiskAccessId = '/subscriptions/<subscription ID>/resourceGroups/<resource group name>/providers/Microsoft.Compute/diskAccesses/<private disk access name>
                Update-AzDisk -ResourceGroup '<resource group name> -DiskName $disk.Name -Disk $disk
        Remediate from Azure CLI
            To configure a disk to allow private access only, run the following command making sure you have the Disk Access ID from a private disk access end point.
                az disk update --name <managed disk name> --resource-group <resource group name> --network-access-policy AllowPrivate --disk-access <disk access ID>
            To completely disable public and private access for a disk, run the following command (still in preview) for each disk:
                az disk update --name <managed disk name> --resource-group <resource group name> --public-network-access Disabled --network-access-policy DenyAll"

  impact 0.5
  tag nist: ['MA-4']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['4.6'] }]

  ref 'https://learn.microsoft.com/en-us/azure/virtual-machines/disks-enable-private-links-for-import-export-portal'
  ref 'https://learn.microsoft.com/en-us/azure/virtual-machines/linux/disks-export-import-private-links-cli'
  ref 'https://learn.microsoft.com/en-us/azure/virtual-machines/disks-restrict-import-export-overview'

  resource_group_and_disk_name = input('resource_group_and_disk_name')
  rg_pattern = resource_group_and_disk_name.map { |rg_disk| "'#{rg_disk}'" }.join(', ')
  ensure_disks_not_public_access_script = %(
    $rg_disk_groups = @(#{rg_pattern})
    foreach ($rg in $rg_disk_groups) {
        $rg = $rg.Trim("'")
        # Split the resource group and disk name
        $names = $rg.Split('\.')
        $resourceGroupName = $names[0]
        $diskName = $names[1]
        # Retrieve the disk using the split names
        $disk = Get-AzDisk -ResourceGroupName $resourceGroupName -DiskName $diskName
        # Check the encryption type
        if ($disk.PublicNetworkAccess -ne "Disabled" -or ($disk.NetworkAccessPolicy -ne "AllowPrivate" -and $disk.NetworkAccessPolicy -ne "DenyAll")) {
            Write-Output "Resource Group: $resourceGroupName, Disk Name: $diskName"
        }
    }
  )
  pwsh_output = powershell(ensure_disks_not_public_access_script)
  describe 'Ensure the number of resource group and disk combinations that has PublicNetworkAccess not set to "Disabled" and NetworkAccessPolicy not set to either "AllowPrivate" or "DenyAll"' do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following resource/disks do not have the correct settings: #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
