control 'azure-foundations-cis-2.1.8' do
    title "Ensure That Microsoft Defender for Containers Is Set To 'On'"
    desc "Turning on Microsoft Defender for Containers enables threat detection for Container
        Registries including Kubernetes, providing threat intelligence, anomaly detection, and
        behavior analytics in the Microsoft Defender for Cloud. The following services will be
        enabled for container instances:
        • Defender agent in Azure
        • Azure Policy for Kubernetes
        • Agentless discovery for Kubernetes
        • Agentless container vulnerability assessment"

    desc 'rationale',
        "Enabling Microsoft Defender for Container Registries allows for greater defense-in-
        depth, with threat detection provided by the Microsoft Security Response Center
        (MSRC)."

    desc 'impact',
        "Turning on Microsoft Defender for Containers incurs an additional cost per resource."

    desc 'check',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Select Environment Settings.
        3. Click on the subscription name.
        4. Select Defender plans.
        5. Ensure On is set under Status for Containers.
        From Azure CLI
        Ensure the output of the commands below indicates Standard pricing.
        For legacy Defender for Container Registries instances:
        az security pricing show --name 'ContainerRegistry' --query pricingTier
        For new Defender for Containers instances:
        az security pricing show --name 'Containers'Page 136
        From PowerShell
        Ensure the output of the commands below indicates Standard pricing.
        For legacy Defender for Container Registries instances:
        Get-AzSecurityPricing -Name 'ContainerRegistry' | Select-Object
        Name,PricingTier
        For new Defender for Containers instances:
        Get-AzSecurityPricing -Name 'Containers' | Select-Object Name,PricingTier
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: 1c988dd6-ade4-430f-a608-2a3e5b0a6d38 - Name: 'Microsoft
        Defender for Containers should be enabled'"

    desc 'fix',
       "From Azure Portal
        1. Go to Microsoft Defender for Cloud.
        2. Select Environment Settings.
        3. Click on the subscription name.
        4. Select Defender plans.
        5. Set Status to On for Containers.
        6. Click Save.
        From Azure CLI
        (Note: 'ContainerRegistry' has been deprecated and is replaced by 'Containers')
        Use the below command to enable Standard pricing tier for Containers.
        az security pricing create -n 'Containers' --tier 'standard'
        From PowerShell
        (Note: 'ContainerRegistry' has been deprecated and is replaced by 'Containers')
        Use the below command to enable Standard pricing tier for Containers.
        Set-AzSecurityPricing -Name 'Containers' -PricingTier 'Standard'"

    impact 0.5
    ref 'mandatory reference link'
    tag nist: ['check NIST SP 800-53, Revision 5']
    tag severity: 'low, medium, or high '
    tag cis_controls: [{ '8.1' => ['check cis controls navigator'] }]

    ref "https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities"
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/list'
    ref 'https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/update'
    ref 'https://docs.microsoft.com/en-us/powershell/module/az.security/get-azsecuritypricing'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities'
    ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction?tabs=defender-for-container-arch-aks'

    describe 'benchmark' do
        skip 'configure'
    end
end