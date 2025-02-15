control 'azure-foundations-cis-8.4' do
  title "Ensure that 'Unattached disks' are encrypted with 'Customer Managed Key' (CMK)"
  desc 'Ensure that unattached disks in a subscription are encrypted with a Customer Managed Key (CMK).'

  desc 'rationale',
       "Managed disks are encrypted by default with Platform-managed keys. Using Customer-managed keys may provide an additional level of security or meet an organization's regulatory requirements. Encrypting managed disks ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads. Even if the disk is not attached to any of the VMs, there is always a risk where a compromised user account with administrative access to VM service can mount/attach these data disks, which may lead to sensitive information disclosure and tampering."

  desc 'impact',
       'NOTE: You must have your key vault set up to utilize this. Encryption is available only on Standard tier VMs. This might cost you more.
        Utilizing and maintaining Customer-managed keys will require additional work to create, protect, and rotate keys.'

  desc 'check',
       %(Audit from Azure Portal
            1. Go to Disks
            2. Click on Add Filter
            3. In the filter field select Disk state
            4. In the Value field select Unattached
            5. Click Apply
            6. For each disk listed ensure that Encryption type in the encryption blade is `Encryption at-rest with a customer-managed key'
        Audit from Azure CLI
            Ensure command below does not return any output.
                az disk list --query '[? diskstate == `Unattached`].{encryptionSettings: encryptionSettings, name: name}' -o json
            Sample Output: [
                                {
                                    "encryptionSettings": null,
                                    "name": "<Disk1>"
                                },
                                {
                                    "encryptionSettings": null,
                                    "name": "<Disk2>"
                                }
                            ]
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: ca91455f-eace-4f96-be59-e6e2c35b4816 - Name: 'Managed disks should be double encrypted with both platform-managed and customer-managed keys')

  desc 'fix',
       "If data stored in the disk is no longer useful, refer to Azure documentation to delete unattached data disks at:
            -https://docs.microsoft.com/en-us/rest/api/compute/disks/delete
            -https://docs.microsoft.com/en-us/cli/azure/disk?view=azure-cli-latest#az-disk-delete
        If data stored in the disk is important, To encrypt the disk refer azure documentation at:
            -https://docs.microsoft.com/en-us/azure/virtual-machines/disks-enable-customer-managed-keys-portal
            -https://docs.microsoft.com/en-us/rest/api/compute/disks/update#encryptionsettings"

  impact 0.5
  tag nist: ['IA-5(1)', 'SC-28', 'SC-28(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.11'] }]

  ref 'https://docs.microsoft.com/en-us/azure/security/fundamentals/azure-disk-encryption-vms-vmss'
  ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-disk-encryption?toc=%2fazure%2fsecurity%2ftoc.json'
  ref 'https://docs.microsoft.com/en-us/rest/api/compute/disks/delete'
  ref 'https://docs.microsoft.com/en-us/cli/azure/disk?view=azure-cli-latest#az-disk-delete'
  ref 'https://docs.microsoft.com/en-us/rest/api/compute/disks/update#encryptionsettings'
  ref 'https://docs.microsoft.com/en-us/cli/azure/disk?view=azure-cli-latest#az-disk-update'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-when-required'

  unattached_list = command("az disk list --query '[? diskstate == `Unattached`].{encryptionSettings: encryptionSettings, name: name}' -o json").stdout.strip

  describe 'Ensure that the number of unattached disks without encryption' do
    subject { unattached_list }
    it 'is 0' do
      expect(subject).to eq('[]')
    end
  end
end
