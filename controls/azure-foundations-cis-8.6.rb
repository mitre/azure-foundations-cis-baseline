control 'azure-foundations-cis-8.6' do
    title "Ensure that 'Enable Data Access Authentication Mode' is 'Checked'"
    desc "Data Access Authentication Mode provides a method of uploading or exporting Virtual Machine Disks."

    desc 'rationale',
        "Enabling data access authentication mode adds a layer of protection using an Entra ID role to further restrict users from creating and using Secure Access Signature (SAS) tokens for exporting a detached managed disk or virtual machine state. Users will need the Data operator for managed disk role within Entra ID in order to download a VHD or VM Guest state using a secure URL."

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

    describe 'benchmark' do
        skip 'configure'
    end
end