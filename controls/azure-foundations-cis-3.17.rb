control 'azure-foundations-cis-3.17' do
    title "Ensure that `Allow Blob Anonymous Access` is set to `Disabled`"
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
       "From Azure Portal:
        1. Open the Storage Accounts blade
        2. Click on a Storage Account
        3. In the storage account menu pane, under the Settings section, click
        Configuration.
        4. Under Allow Blob Anonymous Access ensure that the selected setting is
        Disabled.
        Repeat these steps for each Storage Account.
        Page 231
        From Azure CLI:
        For every storage account in scope:
        az storage account show --Name '<yourStorageAccountName>' --query
        allowBlobPublicAccess
        Ensure that every storage account in scope returns false for the
        'allowBlobPublicAccess' setting.
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 13502221-8df0-4414-9937-de9c5c4e396b - Name: 'Configure your
        Storage account public access to be disallowed'"

    desc 'fix',
       "From Azure Portal:
        1. Open the Storage Accounts blade
        2. Click on a Storage Account
        3. In the storage account menu pane, under the Settings section, click
        Configuration.
        4. Under Allow Blob Anonymous Access, select Disabled.
        Repeat these steps for each Storage Account.
        From Powershell:
        For every storage account in scope, run the following:
        $storageAccount = Get-AzStorageAccount -ResourceGroupName
        '<yourResourceGroup>' -Name '<yourStorageAccountName>'
        $storageAccount.AllowBlobPublicAccess = $false
        Set-AzStorageAccount -InputObject $storageAccount"

    impact 0.5
    tag nist: ['AC-3','AC-5','AC-6','MP-2']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['3.3'] }]

    ref 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent?tabs=portal'
    ref 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent?source=recommendations&tabs=portal'
    ref 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent-classic?tabs=portal'

    describe 'benchmark' do
        skip 'configure'
    end
end