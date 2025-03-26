control 'azure-foundations-cis-8.6' do
  title "Ensure that 'Enable Data Access Authentication Mode' is 'Checked'"
  desc 'Data Access Authentication Mode provides a method of uploading or exporting Virtual Machine Disks.'

  desc 'rationale',
       'Enabling data access authentication mode adds a layer of protection using an Entra ID role to further restrict users from creating and using Secure Access Signature (SAS) tokens for exporting a detached managed disk or virtual machine state. Users will need the Data operator for managed disk role within Entra ID in order to download a VHD or VM Guest state using a secure URL.'

  desc 'impact',
       'In order to apply this setting, the virtual machine to which the disk or disks are attached will need to be powered down and have their disk detached. Users without the Data operator for managed disk role within Entra ID will not be able to export VHD or VM Guest state using the secure download URL.'

  desc 'check',
       "Audit from Azure Portal
            Part A. Select the Virtual Machine to Evaluate
                1. Using the search bar, search for and open the Virtual Machines service.
                2. Click on the name of the Virtual Machine to be audited.
            Part B. Evaluate each Virtual Machine Disk individually
                1. From the selected Virtual Machine resource window, expand the Settings menu item and click Disks.
                2. For each disk, click the name of the disk to open the disk resource window.
                3. From the selected Disk resource window, expand the Settings menu item, and click Disk Export.
            Ensure that Enable Data Access Authentication Mode is checked.
            Repeat Part B for each Disk attached to a VM.
            Repeat Parts A and B to evaluate all Disks in all VMs.
        Audit from PowerShell
            Run the following command for each disk:
                Get-AzDisk -ResourceGroupName '<resource_group_name>' -DiskName '<disk_name>'
            Ensure the DataAccessAuthMode setting displays AzureActiveDirectory next to it.
        Audit from Azure CLI
            Run the following command for each disk:
                az disk show --disk-name ‘<disk_name>’ --resource-group ‘<resource_group_name>’
            Ensure the dataAccessAuthMode setting is set to AzureActiveDirectory"

  desc 'fix',
       "Remediate from Azure Portal
            Part A. Select the Virtual Machine to Remediate
                1. Using the search bar, search for and open the Virtual Machines service.
                2. Click on the name of the Virtual Machine to be remediated.
            Part B. Remediate each Virtual Machine Disk individually
                1. From the selected Virtual Machine resource window, expand the Settings menu item and click Disks.
                2. For each disk, click the name of the disk to open the disk resource window.
                3. From the selected Disk resource window, expand the Settings menu item, and click Disk Export.
            check the checkbox next to Enable Data Access Authentication Mode.
            Repeat Part B for each Disk attached to a VM.
            Repeat Parts A and B to remediate all Disks in all VMs.
        Remediate from PowerShell
            Ensure that each disk is detached from its associated Virtual Machine before proceeding. Once detached, run the following for each disk:
                $disk = Get-AzDisk -ResourceGroupName '<resource_group_name>' -DiskName '<disk_name>'
                $disk.DataAccessAuthMode = 'AzureActiveDirectory' Update-AzDisk -ResourceGroup '<resource_group_name>' -DiskName $disk.Name -Disk $disk
        Remediate from Azure CLI
            Ensure that each disk is detached from its associated Virtual Machine before proceeding. Once detached, run the following for each disk:
                az disk update --name <disk_name> --resource-group <resource_group_name> --data-access-auth-mode AzureActiveDirectory"

  impact 0.5
  tag nist: ['MA-4']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['4.6'] }]

  ref 'https://learn.microsoft.com/en-us/azure/virtual-machines/windows/download-vhd?tabs=azure-portal#secure-downloads-and-uploads-with-microsoft-entra-id'
  ref 'https://learn.microsoft.com/en-us/azure/virtual-machines/windows/download-vhd?tabs=azure-portal#secure-downloads-and-uploads-with-microsoft-entra-id'

  vm_script = 'Get-AzVM | ConvertTo-Json'
  vm_output = powershell(vm_script).stdout.strip
  all_vms = json(content: all_vms).params

  only_if('N/A - No Virtual Machines found', impact: 0) do
    case all_vms
    when Array
      !all_vms.empty?
    when Hash
      !all_vms.empty?
    else
      false
    end
  end

  resource_group_and_disk_name = input('resource_group_and_disk_name')
  rg_pattern = resource_group_and_disk_name.map { |rg_disk| "'#{rg_disk}'" }.join(', ')

  ensure_data_auth_mode_script = %(
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
        if ($disk.DataAccessAuthMode -ne "AzureActiveDirectory") {
            Write-Output "Resource Group: $resourceGroupName, Disk Name: $diskName"
        }
    }
  )

  pwsh_output = powershell(ensure_data_auth_mode_script)

  describe 'Ensure the number of resource group and disk combinations that has DataAccessAuthMode setting not set to AzureActiveDirectory' do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following resource/disks do not have the correct settings: #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
