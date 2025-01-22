control 'azure-foundations-cis-8.8' do
    title 'Ensure that Endpoint Protection for all Virtual Machines is installed'
    desc "Install endpoint protection for all virtual machines."

    desc 'rationale',
        "Installing endpoint protection systems (like anti-malware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. These also offer configurable alerts when known-malicious or unwanted software attempts to install itself or run on Azure systems."

    desc 'impact',
        'Endpoint protection will incur an additional cost to you.'

    desc 'check',
       %(Audit from Azure Portal
            1. Go to Security Center
            2. Click the Recommendations blade
            3. Ensure that there are no recommendations for Endpoint Protection not installed on Azure VMs
        Audit from Azure CLI 
            az vm show -g <MyResourceGroup> -n <MyVm> -d --query "resources[?type=='Microsoft.Compute/virtualMachines/extensions'].{ExtensionName:name}" -o table
            If extensions are installed, it will list the installed extensions. 
                EndpointSecurity || TrendMicroDSA* || Antimalware || EndpointProtection || SCWPAgent || PortalProtectExtension* || FileSecurity*
            Alternatively, you can employ your own endpoint protection tool for your OS
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 1f7c564c-0a90-4d44-b7e1-9d456cffaee8 - Name: 'Endpoint protection should be installed on your machines')

    desc 'fix',
       "Follow Microsoft Azure documentation to install endpoint protection from the security center. Alternatively, you can employ your own endpoint protection tool for your OS."

    impact 0.5
    tag nist: ['SI-3']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['10.2'] }]

    ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-install-endpoint-protection'
    ref 'https://docs.microsoft.com/en-us/azure/security/azure-security-antimalware'
    ref 'https://docs.microsoft.com/en-us/cli/azure/vm/extension?view=azure-cli-latest#az_vm_extension_list'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-security#es-1-use-endpoint-detection-and-response-edr'

    describe 'benchmark' do
        skip 'configure'
    end
end