control 'azure-foundations-cis-8.7' do
    title 'Ensure that Only Approved Extensions Are Installed'
    desc "For added security, only install organization-approved extensions on VMs."

    desc 'rationale',
        "Azure virtual machine extensions are small applications that provide post-deployment configuration and automation tasks on Azure virtual machines. These extensions run with administrative privileges and could potentially access anything on a virtual machine. The Azure Portal and community provide several such extensions. Each organization should carefully evaluate these extensions and ensure that only those that are approved for use are actually implemented."

    desc 'impact',
        'Functionality by unsupported extensions will be disabled.'

    desc 'check',
       "Audit from Azure Portal
            1. Go to Virtual machines.
            2. For each virtual machine, click on the server name to select it go to
            3. In the new column menu, under Settings Click on Extensions + applications.
            4. Ensure that all the listed extensions are approved by your organization for use.
        Audit from Azure CLI 
            Use the below command to list the extensions attached to a VM, and ensure the listed extensions are approved for use. 
                az vm extension list --vm-name <vmName> --resource-group <sourceGroupName> --query [*].name
        Audit From Powershell 
            Get a list of VMs. 
                Get-AzVM
            For each VM run the following command. 
                Get-AzVMExtension -ResourceGroupName <VM Resource Group> -VMName <VM Name>
            Review each Name, ExtensionType, and ProvisioningState to make sure no unauthorized extensions are installed on any virtual machines.
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: c0e996f8-39cf-4af9-9f45-83fbde810432 - Name: 'Only approved VM extensions should be installed'"

    desc 'fix',
       "Remediate from Azure Portal
            1. Go to Virtual machines
            2. For each virtual machine, go to Settings
            3. Click on Extensions + applications
            4. If there are unapproved extensions, uninstall them.
        Remediate from Azure CLI 
            From the audit command identify the unapproved extensions, and use the below CLI command to remove an unapproved extension attached to VM. 
                az vm extension delete --resource-group <resourceGroupName> --vm-name <vmName> --name <extensionName>
        Remediate From Powershell 
            For each VM and each insecure extension from the Audit Procedure run the following command. 
                Remove-AzVMExtension -ResourceGroupName <ResourceGroupName> -Name <ExtensionName> -VMName <VirtualMachineName>"

    impact 0.5
    tag nist: ['CM-8', 'CM-7(1)', 'MA-3']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['2.1'] }]

    ref 'https://docs.microsoft.com/en-us/azure/virtual-machines/windows/extensions-features'
    ref 'https://docs.microsoft.com/en-us/powershell/module/az.compute/?view=azps-7.5.0#vm-extensions'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-asset-management#am-2-use-only-approved-services'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-asset-management#am-5-use-only-approved-applications-in-virtual-machine'

    describe 'benchmark' do
        skip 'configure'
    end
end