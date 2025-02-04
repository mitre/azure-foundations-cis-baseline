control 'azure-foundations-cis-2.22' do
    title "Ensure that 'Require Multi-Factor Authentication to register or join devices with Microsoft Entra ID' is set to 'Yes'"
    desc "NOTE: This recommendation is only relevant if your subscription is using Per-User
        MFA. If your organization is licensed to use Conditional Access, the preferred method of
        requiring MFA to join devices to Entra ID is to use a Conditional Access policy (see
        additional information below for link).
        Joining or registering devices to Microsoft Entra ID should require multi-factor
        authentication."

    desc 'rationale',
        "Multi-factor authentication is recommended when adding devices to Microsoft Entra ID.
        When set to Yes, users who are adding devices from the internet must first use the
        second method of authentication before their device is successfully added to the
        directory. This ensures that rogue devices are not added to the domain using a
        compromised user account. Note: Some Microsoft documentation suggests to use
        conditional access policies for joining a domain from certain whitelisted networks or
        devices. Even with these in place, using Multi-Factor Authentication is still
        recommended, as it creates a process for review before joining the domain."

    desc 'impact',
        "A slight impact of additional overhead, as Administrators will now have to approve every access to the domain."

    desc 'check',
       "From Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Devices
        4. Select Device settings
        5. Ensure that Require Multi-Factor Authentication to register or join
        devices with Microsoft Entra is set to Yes"

    desc 'fix',
       "Remediate from Azure Portal
        1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Under Manage, select Devices
        4. Under Manage, select Device settings
        5. Under Microsoft Entra join and registration settings, set Require
        Multifactor Authentication to register or join devices with
        Microsoft Entra to Yes
        6. Click Save"

    impact 0.5
    tag nist: ['IA-2(1)','IA-2(2)','AC-19','IA-2(1)','IA-2(2)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['6.3','6.4'] }]

    ref 'https://blogs.technet.microsoft.com/janketil/2016/02/29/azure-mfa-for-enrollment-in-intune-and-azure-ad-device-registration-explained/'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-6-use-strong-authentication-controls'

    describe "Ensure that 'Require Multi-Factor Authentication to register or join devices with Microsoft Entra ID' is set to 'Yes'" do
        skip 'The check for this control needs to be done manually'
    end
end