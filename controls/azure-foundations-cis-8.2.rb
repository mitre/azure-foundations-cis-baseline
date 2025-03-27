control 'azure-foundations-cis-8.2' do
  title 'Ensure Virtual Machines are utilizing Managed Disks'
  desc "Migrate blob-based VHDs to Managed Disks on Virtual Machines to exploit the default features of this configuration. The features include:
            1. Default Disk Encryption
            2. Resilience, as Microsoft will managed the disk storage and move around if underlying hardware goes faulty
            3. Reduction of costs over storage accounts"

  desc 'rationale',
       "Managed disks are by default encrypted on the underlying hardware, so no additional encryption is required for basic protection. It is available if additional encryption is required. Managed disks are by design more resilient that storage accounts.
        For ARM-deployed Virtual Machines, Azure Adviser will at some point recommend moving VHDs to managed disks both from a security and cost management perspective."

  desc 'impact',
       'There are additional costs for managed disks based off of disk space allocated. When converting to managed disks, VMs will be powered off and back on.'

  desc 'check',
       %(Audit from Azure Portal
            1. Using the search feature, go to Virtual Machines
            2. Click the Manage view dropdown, then select Edit columns
            3. Add Uses managed disks to the selected columns
            4. Select Save
            5. Ensure all virtual machines listed are using managed disks
        Audit From Powershell
            Run the following command:
                Get-AzVM | ForEach-Object {"Name: " + $_.Name;"ManagedDisk Id: " + $_.StorageProfile.OsDisk.ManagedDisk.Id;""}
            Example output:
                Name: vm1
                ManagedDisk Id: /disk1/id

                Name: vm2
                ManagedDisk Id: /disk2/id

                If the 'ManagedDisk Id' field is empty the os disk for that vm is not managed.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 06a78e20-9358-41c9-923c-fb736d382a4d - Name: 'Audit VMs that do not use managed disks')

  desc 'fix',
       "Remediate from Azure Portal
            1. Using the search feature, go to Virtual Machines
            2. Select the virtual machine you would like to convert
            3. Select Disks in the menu for the VM
            4. At the top select Migrate to managed disks
            5. You may follow the prompts to convert the disk and finish by selecting Migrate to start the process
            NOTE VMs will be stopped and restarted after migration is complete.
        Remediate From Powershell
            Stop-AzVM -ResourceGroupName $rgName -Name $vmName -Force ConvertTo-AzVMManagedDisk -ResourceGroupName $rgName -VMName $vmName
            Start-AzVM -ResourceGroupName $rgName -Name $vmName"

  impact 0.5
  tag nist: ['IA-5(1)', 'SC-28', 'SC-28(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.11'] }]

  ref 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/convert-unmanaged-to-managed-disks'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-4-enable-data-at-rest-encryption-by-default'
  ref 'https://docs.microsoft.com/en-us/azure/virtual-machines/faq-for-disks'
  ref 'https://azure.microsoft.com/en-us/pricing/details/managed-disks/'

  vm_script = 'Get-AzVM | ConvertTo-Json'
  vm_output = powershell(vm_script).stdout.strip
  all_vms = json(content: vm_output).params

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

  ensure_vms_using_managed_disks_script = %(
    $vmNames = Get-AzVM | ForEach-Object {
    if (-not $_.StorageProfile.OsDisk.ManagedDisk.Id) {
        $_.Name
        }
    }
    $vmNames -join ', '
  )

  pwsh_output = powershell(ensure_vms_using_managed_disks_script)

  describe 'Ensure the number of VMs with ManagedDisk state empty' do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following locations do not have Network Watchers: #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
