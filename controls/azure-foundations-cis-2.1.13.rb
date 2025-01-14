control 'azure-foundations-cis-2.1.13' do
    title "Ensure that Microsoft Cloud Security Benchmark policies are not set to 'Disabled'"
    desc "The Microsoft Cloud Security Benchmark (or 'MCSB') is an Azure Policy Initiative
        containing many security policies to evaluate resource configuration against best
        practice recommendations. If a policy in the MCSB is set with effect type Disabled, it is
        not evaluated and may prevent administrators from being informed of valuable security
        recommendations."

    desc 'rationale',
        "A security policy defines the desired configuration of resources in your environment and
        helps ensure compliance with company or regulatory security requirements. The MCSB
        Policy Initiative a set of security recommendations based on best practices and is
        associated with every subscription by default. When a policy 'Effect' is set to Audit,
        policies in the MCSB ensure that Defender for Cloud evaluates relevant resources for
        supported recommendations. To ensure that policies within the MCSB are not being
        missed when the Policy Initiative is evaluated, none of the policies should have an
        Effect of Disabled."

    desc 'impact',
        "Policies within the MCSB default to an effect of Audit and will evaluate - but not enforce
        - policy recommendations. Ensuring these policies are set to Audit simply ensures that
        the evaluation occurs to allow administrators to understand where an improvement may
        be possible. Administrators will need to determine if the recommendations are relevant
        and desirable for their environment, then manually take action to resolve the status if
        desired."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Then Environment Settings
        4. Select the appropriate Subscription
        5. Click on Security Policy in the left column.
        6. Click on Microsoft Cloud Security Benchmark
        7. Click Add Filter and select Effect
        8. Check the Disabled box to search for all disabled policies
        9. Click Apply
        Page 150
        If no Policies are shown, no Policies are in Disabled status and no remediation is
        necessary.
        If any Policies remain in the list, the policy Effect should be changed to Audit."

    desc 'fix',
       "From Azure Portal
        Part A - List all disabled policies
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Defender for Cloud
        3. Then Environment Settings
        4. Select the appropriate Subscription
        5. Click on Security Policy in the left column.
        6. Click on Microsoft Cloud Security Benchmark
        7. Click Add Filter and select Effect
        8. Check the Disabled box to search for all disabled policies
        9. Click Apply
        Part B - Remediate Policy Effect
        For each policy that remains in the list:
        1. Click the blue ellipses ... to the right of the policy name
        2. Click Manage effect and parameters
        3. Under Policy Effect, select the Audit radio button
        4. Click Save
        5. Click Refresh
        Repeat 'Part B - Remediate Policy Effect' until no more policies are listed."

    impact 0.5
    tag nist: ['check NIST SP 800-53, Revision 5']
    tag severity: 'low, medium, or high '
    tag cis_controls: [{ '8.1' => ['check cis controls navigator'] }]

    ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-policies'
    ref 'https://docs.microsoft.com/en-us/azure/security-center/security-center-enable-transparent-data-encryption'
    ref 'https://msdn.microsoft.com/en-us/library/mt704062.aspx'
    ref 'https://msdn.microsoft.com/en-us/library/mt704063.aspx'
    ref 'https://docs.microsoft.com/en-us/rest/api/policy/policy-assignments/get'
    ref 'https://docs.microsoft.com/en-us/rest/api/policy/policy-assignments/create'
    ref 'https://docs.microsoft.com/en-in/azure/security-center/tutorial-security-policy'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-7-define-and-implement-logging-threat-detection-and-incident-response-strategy'

    describe 'benchmark' do
        skip 'configure'
    end
end