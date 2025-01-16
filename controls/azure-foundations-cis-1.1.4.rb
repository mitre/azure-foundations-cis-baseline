control 'azure-foundations-cis-1.1.4' do
    title "Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is Disabled"
    desc "Do not allow users to remember multi-factor authentication on devices"

    desc 'rationale',
        "Remembering Multi-Factor Authentication (MFA) for devices and browsers allows users
        to have the option to bypass MFA for a set number of days after performing a
        successful sign-in using MFA. This can enhance usability by minimizing the number of
        times a user may need to perform two-step verification on the same device. However, if
        an account or device is compromised, remembering MFA for trusted devices may affect
        security. Hence, it is recommended that users not be allowed to bypass MFA."

    desc 'impact',
        "For every login attempt, the user will be required to perform multi-factor authentication."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Users
        4. Click the Per-user MFA button on the top bar
        5. Click on service settings
        6. Ensure that Allow users to remember multi-factor authentication on
        devices they trust is not enabled"

    desc 'fix',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Users
        4. Click the Per-user MFA button on the top bar
        5. Click on service settings
        6. Uncheck the box next to Allow users to remember multi-factor
        authentication on devices they trust"

    impact 0.5
    tag nist: ['IA-2(1)','IA-2(2)','AC-19','IA-2(1)','IA-2(2)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['6.3','6.4'] }]

    ref 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings#remember-multi-factor-authentication-for-devices-that-users-trust'
    ref 'https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-4-use-strong-authentication-controls-for-all-azure-active-directory-based-access'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-6-use-strong-authentication-controls'

    describe 'benchmark' do
        skip 'configure'
    end
end