control 'azure-foundations-cis-4.16' do
    title "Ensure 'Cross Tenant Replication' is not enabled"
    desc "Cross Tenant Replication in Azure allows data to be replicated across multiple Azure
        tenants. While this feature can be beneficial for data sharing and availability, it also
        poses a significant security risk if not properly managed. Unauthorized data access,
        data leakage, and compliance violations are potential risks. Disabling Cross Tenant
        Replication ensures that data is not inadvertently replicated across different tenant
        boundaries without explicit authorization."

    desc 'rationale',
        "Disabling Cross Tenant Replication minimizes the risk of unauthorized data access and
        ensures that data governance policies are strictly adhered to. This control is especially
        critical for organizations with stringent data security and privacy requirements, as it
        prevents the accidental sharing of sensitive information."

    desc 'impact',
        "Disabling Cross Tenant Replication may affect data availability and sharing across
        different Azure tenants. Ensure that this change aligns with your organizational data
        sharing and availability requirements."

    desc 'check',
       "Audit from Azure Portal
        1. Go to Storage Accounts.
        2. For each storage account, under Data management, click Object replication.
        3. Click Advanced settings.
        4. Ensure Allow cross-tenant replication is not checked.
        Audit from Azure CLI
        az storage account list --query '[*].[name,allowCrossTenantReplication]''
        The value of false should be returned for each storage account listed.
        Audit from Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 92a89a79-6c52-4a7e-a03f-61306fc49312 - Name: 'Storage accounts
        should prevent cross tenant object replication'"

    desc 'fix',
       "Remediate from Azure Portal
        1. Go to Storage Accounts.
        2. For each storage account, under Data management, click Object replication.
        3. Click Advanced settings.
        4. Uncheck Allow cross-tenant replication.
        5. Click OK.
        Remediate from Azure CLI
        Replace the information within <> with appropriate values:
        az storage account update --name <storageAccountName> --resource-group
        <resourceGroupName> --allow-cross-tenant-replication false"

    impact 0.5
    tag nist: ['AC-3','AC-5','AC-6','MP-2']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['3.3'] }]

    ref 'https://learn.microsoft.com/en-us/azure/storage/blobs/object-replication-prevent-cross-tenant-policies?tabs=portal'

    storage_accounts = json(command:"az storage account list --query \"[*].[name,allowCrossTenantReplication]\" --output json").params

    storage_accounts.each do |account|
        account_name = account[0]
        allow_replication = account[1]

        describe "Storage Account: #{account_name}" do
            it 'should have allowCrossTenantReplication set to false' do
                expect(allow_replication).to cmp false
            end
        end
    end
end