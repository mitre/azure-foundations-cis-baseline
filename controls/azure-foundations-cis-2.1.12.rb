control 'azure-foundations-cis-2.1.12' do
    title "Ensure that Microsoft Defender Recommendation for 'Apply system updates' status is 'Completed'"
    desc "Ensure that the latest OS patches for all virtual machines are applied."

    desc 'rationale',
        "Windows and Linux virtual machines should be kept updated to:
        • Address a specific bug or flaw
        • Improve an OS or application’s general stability
        • Fix a security vulnerability
        Microsoft Defender for Cloud retrieves a list of available security and critical updates
        from Windows Update or Windows Server Update Services (WSUS), depending on
        which service is configured on a Windows VM. The security center also checks for the
        latest updates in Linux systems. If a VM is missing a system update, the security center
        will recommend system updates be applied."
    desc 'impact',
        "Running Microsoft Defender for Cloud incurs additional charges for each resource
        monitored. Please see attached reference for exact charges per hour."
        
    desc 'check',
        "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Then the Recommendations blade
        4. Ensure that there are no recommendations for Apply system updates
        Alternatively, you can employ your own patch assessment and management tool to
        periodically assess, report and install the required security patches for your OS.
        Page 148
        From Azure Policy
        If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the
        associated Policy definition in Azure.
        If referencing a printed copy, you can search Policy IDs from this URL:
        https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
        • Policy ID: bd876905-5b84-4f73-ab2d-2e7a7c4568d9 - Name: '[Preview]:
        Machines should be configured to periodically check for missing system updates'"

    desc 'fix',
       "Follow Microsoft Azure documentation to apply security patches from the security
        center. Alternatively, you can employ your own patch assessment and management tool
        to periodically assess, report, and install the required security patches for your OS."

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-posture-vulnerability-management#pv-6-rapidly-and-automatically-remediate-vulnerabilities'
    ref 'https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/'
    ref 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-vm'

    describe 'benchmark' do
        skip 'configure'
    end
end