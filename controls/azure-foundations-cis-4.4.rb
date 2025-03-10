control 'azure-foundations-cis-4.4' do
  title 'Ensure that Storage Account Access Keys are Periodically Regenerated'
  desc 'For increased security, regenerate storage account access keys periodically.'

  desc 'rationale',
       "When a storage account is created, Azure generates two 512-bit storage access keys
        which are used for authentication when the storage account is accessed. Rotating these
        keys periodically ensures that any inadvertent access or exposure does not result from
        the compromise of these keys.
        Cryptographic key rotation periods will vary depending on your organization's security
        requirements and the type of data which is being stored in the Storage Account. For
        example, PCI DSS mandates that cryptographic keys be replaced or rotated 'regularly,'
        and advises that keys for static data stores be rotated every 'few months.'
        For the purposes of this recommendation, 90 days will prescribed for the reminder.
        Review and adjustment of the 90 day period is recommended, and may even be
        necessary. Your organization's security requirements should dictate the appropriate
        setting."

  desc 'impact',
       "Regenerating access keys can affect services in Azure as well as the organization's
        applications that are dependent on the storage account. All clients who use the access
        key to access the storage account must be updated to use the new key."

  desc 'check',
       "From Azure Portal
        1. Go to Storage Accounts
        2. For each Storage Account, go to Access keys
        3. Review the date in the Last rotated field for each key.
        If the Last rotated field indicates value greater than 90 day [or greater than your
        organization's period of validity], the key should be rotated.
        From Azure CLI
        1. Get a list of storage accounts
        az storage account list --subscription <subscription-id>
        Make a note of id, name and resourceGroup.
        2. For every storage account make sure that key is regenerated in past 90 days.
        az monitor activity-log list --namespace Microsoft.Storage --offset 90d --
        query '[?contains(authorization.action, 'regenerateKey')]' --resource-id
        <resource id>
        The output should contain
        'authorization'/'scope': <your_storage_account> AND 'authorization'/'action':
        'Microsoft.Storage/storageAccounts/regeneratekey/action' AND
        'status'/'localizedValue': 'Succeeded' 'status'/'Value': 'Succeeded'"

  desc 'fix',
       "From Azure Portal
        1. Go to Storage Accounts
        2. For each Storage Account with outdated keys, go to Access keys
        3. Click Rotate key next to the outdated key, then click Yes to the prompt confirming
        that you want to regenerate the access key.
        After Azure regenerates the Access Key, you can confirm that Access keys reflects a
        Last rotated date of (0 days ago)."

  impact 0.5
  tag nist: ['MA-4', 'AC-1', 'AC-2', 'AC-2(1)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['4.6', '6.2'] }]

  ref 'https://docs.microsoft.com/en-us/azure/storage/common/storage-create-storage-account#regenerate-storage-access-keys'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-2-protect-identity-and-authentication-systems'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'
  ref 'https://www.pcidssguide.com/pci-dss-key-rotation-requirements/'
  ref 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf'

  describe 'benchmark' do
    skip 'The check for this control needs to be done manually'
  end
end
