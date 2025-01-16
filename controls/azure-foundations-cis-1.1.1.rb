control 'azure-foundations-cis-1.1.1' do
    title 'Ensure Security Defaults is enabled on Microsoft Entra ID'
    desc "Security defaults in Microsoft Entra ID make it easier to be secure and help protect your
        organization. Security defaults contain preconfigured security settings for common
        attacks.
        Security defaults is available to everyone. The goal is to ensure that all organizations
        have a basic level of security enabled at no extra cost. You may turn on security
        defaults in the Azure portal."

    desc 'rationale',
        "Security defaults provide secure default settings that we manage on behalf of
        organizations to keep customers safe until they are ready to manage their own identity
        security settings.
        For example, doing the following:
        • Requiring all users and admins to register for MFA.
        • Challenging users with MFA - when necessary, based on factors such as
        location, device, role, and task.
        • Disabling authentication from legacy authentication clients, which can’t do MFA."
    
    desc 'impact',
        "This recommendation should be implemented initially and then may be overridden by
        other service/product specific CIS Benchmarks. Administrators should also be aware
        that certain configurations in Microsoft Entra ID may impact other Microsoft services
        such as Microsoft 365."

    desc 'check',
       "From Azure Portal
        To ensure security defaults is enabled in your directory:
        1. From Azure Home select the Portal Menu.
        2. Browse to Microsoft Entra ID > Properties.
        3. Select Manage security defaults.
        4. Verify the Enable security defaults toggle is Enabled."

    desc 'fix',
       "From Azure Portal
        To enable security defaults in your directory:
        1. From Azure Home select the Portal Menu.
        2. Browse to Microsoft Entra ID > Properties
        3. Select Manage security defaults
        4. Set the Enable security defaults to Enabled
        5. Select Save"

    impact 0.5
    tag nist: ['CM-1','CM-2','CM-6','CM-7','CM-7(1)','CM-9','SA-3','SA-8','SA-10']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['4.1'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults'
    ref 'https://techcommunity.microsoft.com/t5/azure-active-directory-identity/introducing-security-defaults/ba-p/1061414'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-2-protect-identity-and-authentication-systems'

    describe 'benchmark' do
        skip 'configure'
    end
end