control 'azure-foundations-cis-8.3' do
  title "Ensure that 'OS and Data' disks are encrypted with Customer Managed Key (CMK)"
  desc 'Ensure that OS disks (boot volumes) and data disks (non-boot volumes) are encrypted with CMK (Customer Managed Keys). Customer Managed keys can be either ADE or Server Side Encryption (SSE).'

  desc 'rationale',
       "Encrypting the IaaS VM's OS disk (boot volume) and Data disks (non-boot volume) ensures that the entire content is fully unrecoverable without a key, thus protecting the volume from unwanted reads. PMK (Platform Managed Keys) are enabled by default in Azure-managed disks and allow encryption at rest. CMK is recommended because it gives the customer the option to control which specific keys are used for the encryption and decryption of the disk. The customer can then change keys and increase security by disabling them instead of relying on the PMK key that remains unchanging. There is also the option to increase security further by using automatically rotating keys so that access to disk is ensured to be limited. Organizations should evaluate what their security requirements are, however, for the data stored on the disk. For high-risk data using CMK is a must, as it provides extra steps of security. If the data is low risk, PMK is enabled by default and provides sufficient data security."

  desc 'impact',
       'Using CMK/BYOK will entail additional management of keys.
        NOTE: You must have your key vault set up to utilize this.'

  desc 'check',
       %(Audit from Azure Portal
            1. Go to Virtual machines
            2. For each virtual machine, go to Settings
            3. Click on Disks
            4. Ensure that the OS disk and Data disks have encryption set to CMK.
        Audit From Powershell
            $ResourceGroupName="yourResourceGroupName"
            $DiskName="yourDiskName"
            $disk=Get-AzDisk -ResourceGroupName
            $ResourceGroupName -DiskName $DiskName $disk.Encryption.Type
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 0961003e-5a0a-4549-abde-af6a37f2724d - Name: 'Virtual machines should encrypt temp disks, caches, and data flows between Compute and Storage resources')

  desc 'fix',
       "Remediate from Azure Portal
            Note: Disks must be detached from VMs to have encryption changed.
                1. Go to Virtual machines
                2. For each virtual machine, go to Settings
                3. Click on Disks
                4. Click the ellipsis (...), then click Detach to detach the disk from the VM
                5. Now search for Disks and locate the unattached disk
                6. Click the disk then select Encryption
                7. Change your encryption type, then select your encryption set
                8. Click Save
                9. Go back to the VM and re-attach the disk
        Remediate From Powershell
            $KVRGname = 'MyKeyVaultResourceGroup';
            $VMRGName = 'MyVirtualMachineResourceGroup';
            $vmName = 'MySecureVM';
            $KeyVaultName = 'MySecureVault';
            $KeyVault = Get-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $KVRGname;
            $diskEncryptionKeyVaultUrl = $KeyVault.VaultUri;
            $KeyVaultResourceId = $KeyVault.ResourceId;
            Set-AzVMDiskEncryptionExtension -ResourceGroupName $VMRGname -VMName $vmName -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $KeyVaultResourceId;
            NOTE: During encryption it is likely that a reboot will be required. It may take up to 15 minutes to complete the process.
            NOTE 2: This may differ for Linux machines as you may need to set the -skipVmBackup parameter"

  impact 0.5
  tag nist: ['IA-5(1)', 'SC-28', 'SC-28(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.11'] }]

  ref 'https://docs.microsoft.com/azure/security/fundamentals/azure-disk-encryption-vms-vmsss'
  ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-disk-encryption?toc=%2fazure%2fsecurity%2ftoc.json'
  ref 'https://docs.microsoft.com/azure/security/fundamentals/data-encryption-best-practices#protect-data-at-resthttps://docs.microsoft.com/azure/virtual-machines/windows/disk-encryption-portal-quickstart'
  ref 'https://docs.microsoft.com/en-us/rest/api/compute/disks/delete'
  ref 'https://docs.microsoft.com/en-us/rest/api/compute/disks/update#encryptionsettings'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-when-required'
  ref 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disks-enable-customer-managed-keys-powershell'
  ref 'https://docs.microsoft.com/en-us/azure/virtual-machines/disk-encryption'

  vm_script = 'Get-AzVM | ConvertTo-Json -Depth 10'
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

  ensure_disks_encrypted_cmk_script = %(
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
    if ($disk.Encryption.Type -ne "EncryptionAtRestWithPlatformKey" -and $disk.Encryption.Type -ne "EncryptionAtRestWithCustomerKey") {
        Write-Output "Resource Group: $resourceGroupName, Disk Name: $diskName, Encryption Type: $($disk.Encryption.Type)"
        }
    }
  )

  pwsh_output = powershell(ensure_disks_encrypted_cmk_script)

  describe 'Ensure the number of resource group and disk combinations that do not have encryption state set to either "EncryptionAtRestWithCustomerKey" or "EncryptionAtRestWithPlatformKey"' do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following resource/disks do not have the correct encryption state: #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
