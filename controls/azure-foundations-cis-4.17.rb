control 'azure-foundations-cis-4.17' do
  title 'Ensure that `Allow Blob Anonymous Access` is set to `Disabled`'
  desc "The Azure Storage setting ‘Allow Blob Anonymous Access’ (aka
        'allowBlobPublicAccess') controls whether anonymous access is allowed for blob data
        in a storage account. When this property is set to True, it enables public read access to
        blob data, which can be convenient for sharing data but may carry security risks. When
        set to False, it disallows public access to blob data, providing a more secure storage
        environment."

  desc 'rationale',
       "If 'Allow Blob Anonymous Access' is enabled, blobs can be accessed by adding the
        blob name to the URL to see the contents. An attacker can enumerate a blob using
        methods, such as brute force, and access them.
        Exfiltration of data by brute force enumeration of items from a storage account may
        occur if this setting is set to 'Enabled'."

  desc 'impact',
       "Additional consideration may be required for exceptional circumstances where elements
        of a storage account require public accessibility. In these circumstances, it is highly
        recommended that all data stored in the public facing storage account be reviewed for
        sensitive or potentially compromising data, and that sensitive or compromising data is
        never stored in these storage accounts."

  desc 'check',
       "Audit from Azure Portal
        1. Go to Storage Accounts.
        2. For each storage account, under Settings, click Configuration.
        3. Ensure Allow Blob Anonymous Access is set to Disabled.
        Audit from Azure CLI
        For every storage account in scope:
        az storage account show --name '<yourStorageAccountName>' --query
        allowBlobPublicAccess
        Ensure that every storage account in scope returns false for the
        'allowBlobPublicAccess' setting.
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 4fa4b6c0-31ca-4c0d-b10d-24b96f62a751 - Name: '[Preview]: Storage
        account public access should be disallowed'"

  desc 'fix',
       "Remediate from Azure Portal
        1. Go to Storage Accounts.
        2. For each storage account, under Settings, click Configuration.
        3. Set Allow Blob Anonymous Access to Disabled.
        4. Click Save.
        Remediate from Powershell
        For every storage account in scope, run the following:
        $storageAccount = Get-AzStorageAccount -ResourceGroupName
        '<yourResourceGroup>' -Name '<yourStorageAccountName>'
        $storageAccount.AllowBlobPublicAccess = $false
        Set-AzStorageAccount -InputObject $storageAccount"

  impact 0.5
  tag nist: ['AC-3', 'AC-5', 'AC-6', 'MP-2']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.3'] }]

  ref 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent?tabs=portal'
  ref 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent?source=recommendations&tabs=portal'
  ref 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent-classic?tabs=portal'

  storage_script = 'Get-AzStorageAccount | ConvertTo-Json -Depth 10'
  storage_output = powershell(storage_script).stdout.strip
  all_storage = json(content: storage_output).params

  only_if('N/A - No Storage Accounts found', impact: 0) do
    case all_storage
    when Array
      !all_storage.empty?
    when Hash
      !all_storage.empty?
    else
      false
    end
  end

  rg_sa_list = input('resource_groups_and_storage_accounts')

  rg_sa_list.each do |pair|
    resource_group, storage_account = pair.split('.')

    allow_blob_public_access = json(command: "az storage account show --name #{storage_account} --query allowBlobPublicAccess").params

    describe "Storage Account: #{storage_account} (Resource Group: #{resource_group})" do
      it "should have allowBlobPublicAccess set to 'False'" do
        expect(allow_blob_public_access).to cmp false
      end
    end
  end
end
