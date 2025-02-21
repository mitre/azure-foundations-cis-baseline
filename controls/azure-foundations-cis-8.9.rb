control 'azure-foundations-cis-8.9' do
  title '[Legacy] Ensure that VHDs are Encrypted'
  desc "Description:
        NOTE: This is a legacy recommendation. Managed Disks are encrypted by default and recommended for all new VM implementations.
        VHD (Virtual Hard Disks) are stored in blob storage and are the old-style disks that were attached to Virtual Machines. The blob VHD was then leased to the VM. By default, storage accounts are not encrypted, and Microsoft Defender will then recommend that the OS disks should be encrypted. Storage accounts can be encrypted as a whole using PMK or CMK. This should be turned on for storage accounts containing VHDs."

  desc 'rationale',
       'While it is recommended to use Managed Disks which are encrypted by default, "legacy" VHDs may exist for a variety of reasons and may need to remain in VHD format. VHDs are not encrypted by default, so this recommendation intends to address the security of these disks. In these niche cases, VHDs should be encrypted using the procedures in this recommendation to encrypt and protect the data content.
        If a virtual machine is using a VHD and can be converted to a managed disk, instructions for this procedure can be found in the resources section of this recommendation under the title "Convert VHD to Managed Disk."'

  desc 'impact',
       'Depending on how the encryption is implemented will change the size of the impact. If provider-managed keys(PMK) are utilized, the impact is relatively low, but processes need to be put in place to regularly rotate the keys. If Customer-managed keys(CMK) are utilized, a key management process needs to be implemented to store and manage key rotation, thus the impact is medium to high depending on user maturity with key management.'

  desc 'check',
       "Audit from Azure CLI
            For each virtual machine identify if the VM is using a legacy VHD by reviewing the VHD parameter in the output of the following command. The VHD parameter will contain the Storage Account name used for the VHD.
                az vm show --name <MyVM> --resource-group <MyResourceGroup>
            Next, identify if the storage account from the VHD parameter is encrypted by reviewing the encryption --> services --> blob --> enabled within the output of the following command and make sure its value is True.
                az storage account show --name <storage account name> --resource-group <resource group>
        Audit From Powershell:
            Determine whether the VM is using a VHD for the OS Disk and any Data disks.
                $virtualMachine = Get-AzVM --Name <vm name> --ResourceGroup <resource group name> |Select-Object -ExpandProperty StorageProfile
                $virtualMachine.OsDisk
                $virtualMachine.DataDisks
            Next, use the value from VHD to see if the storage blob holding the VHD is encrypted.
                $storageAccount = Get-AzStorageAccount -Name <storage account name from VHD setting> -ResourceGroupName <resource group name>
                $storageAccount.Encryption.Services.Blob
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 702dd420-7fcc-42c5-afe8-4026edd20fe0 - Name: 'OS and data disks should be encrypted with a customer-managed key'"

  desc 'fix',
       "Remediate from Azure Portal
            1. Navigate to the storage account that you wish to encrypt
            2. Select encryption
            3. Select the encryption type that you wish to use
            If you wish to use a Microsoft-managed key (the default), you can save at this point and encryption will be applied to the account. If you select Customer-managed keys, it will ask for the location of the key (The default is an Azure Key Vault) and the key name. Once these are captured, save the configuration and the account will be encrypted using the provided key.
        Remediate from Azure CLI:
            Create the Key Vault
                az keyvault create --name <name> --resource-group <resourceGroup> --location <location> --enabled-for-disk-encryption
            Encrypt the disk and store the key in Key Vault
                az vm encryption enable -g <resourceGroup> --name <name> --disk-encryption-keyvault myKV
        Remediate From Powershell
            This process uses a Key Vault to store the keys
            Create the Key Vault
                New-AzKeyvault -name <name> -ResourceGroupName <resourceGroup> -Location <location> -EnabledForDiskEncryption
            Encrypt the disk and store the key in Key Vault
                $KeyVault = Get-AzKeyVault -VaultName <name> -ResourceGroupName <resourceGroup>
                Set-AzVMDiskEncryptionExtension -ResourceGroupName <resourceGroup> -VMName <name> -DiskEncryptionKeyVaultUrl $KeyVault.VaultUri -DiskEncryptionKeyVaultId $KeyVault.ResourceId"

  impact 0.5
  tag nist: ['IA-5(1)', 'SC-28', 'SC-28(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.11'] }]

  ref 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-cli-quickstart'
  ref 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-powershell-quickstart'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-4-enable-data-at-rest-encryption-by-default'
  ref 'https://docs.microsoft.com/en-us/previous-versions/azure/virtual-machines/scripts/virtual-machines-powershell-sample-create-managed-disk-from-vhd'

  only_approved_extensions_approved_script = %(
    $vms = Get-AzVM

    # Iterate over each VM
    foreach ($vm in $vms) {
        $vmName = $vm.Name
        $resourceGroupName = $vm.ResourceGroupName

        # Get all extensions for the current VM
        $virtualMachine = Get-AzVM --Name $vmName -ResourceGroup $resourceGroupName |Select-Object -ExpandProperty StorageProfile
        $osDisk = $virtualMachine.OsDisk
        $dataDisk = $virtualMachine.DataDisks

        if ($osDisk.Vhd) {
            # Get the VHD URI
            $osDiskUri = $osDisk.Vhd.Uri
            Write-Host "OS Disk VHD URI: $osDiskUri"

            # Extract the VHD name from the URI
            $osDiskVhdName = [System.IO.Path]::GetFileName($osDiskUri)
            $storageAccount = Get-AzStorageAccount -Name $osDiskVhdName -ResourceGroupName $resourceGroupName

            $blobEncryption = $storageAccount.Encryption.Services.Blob

            # Check if blob encryption is enabled
            if (-not $blobEncryption.Enabled) {
                Write-Host "Blob encryption is NOT enabled for storage account $storageAccountName in $vmName VM and $resourceGroupName resource group."
            }
        }
        else {
            Write-Host "The $vmName VM and $resourceGroupName resource group does not have a OS Disk with VHD"
        }
    }
  )
  pwsh_output = powershell(only_approved_extensions_approved_script)
  describe 'Ensure the number of resource group/VMs that has storageAccount.Encryption.Services.Blob set to False' do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following resource groups/VM do not have the the approved settings are: #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
