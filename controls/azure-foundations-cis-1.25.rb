control 'azure-foundations-cis-1.25' do
    title 'Ensure fewer than 5 users have global administrator assignment'
    desc "This recommendation aims to maintain a balance between security and operational
        efficiency by ensuring that a minimum of 2 and a maximum of 4 users are assigned the
        Global Administrator role in Microsoft Entra ID. Having at least two Global
        Administrators ensures redundancy, while limiting the number to four reduces the risk of
        excessive privileged access."

    desc 'rationale',
        "The Global Administrator role has extensive privileges across all services in Microsoft
        Entra ID. The Global Administrator role should never be used in regular daily activities;
        administrators should have a regular user account for daily activities, and a separate
        account for administrative responsibilities. Limiting the number of Global Administrators
        helps mitigate the risk of unauthorized access, reduces the potential impact of human
        error, and aligns with the principle of least privilege to reduce the attack surface of an
        Azure tenant. Conversely, having at least two Global Administrators ensures that
        administrative functions can be performed without interruption in case of unavailability of
        a single admin."

    desc 'impact',
        "Implementing this recommendation may require changes in administrative workflows or
        the redistribution of roles and responsibilities. Adequate training and awareness should
        be provided to all Global Administrators."

    desc 'check',
       "1. From Azure Home select the Portal Menu
        2. Select Microsoft Entra ID
        3. Select Roles and Administrators
        4. Select Global Administrator
        5. Ensure less than 5 users are actively assigned the role.
        6. Ensure that at least 2 users are actively assigned the role."

    desc 'fix',
       "If more 4 users are assigned:
        1. Remove Global Administrator role for users which do not or no longer require the
        role.
        Page 111
        2. Assign Global Administrator role via PIM which can be activated when required.
        3. Assign more granular roles to users to conduct their duties.
        If only one user is assigned:
        1. Provide the Global Administrator role to a trusted user or create a break glass
        admin account."

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    ref 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices#5-limit-the-number-of-global-administrators-to-less-than-5'
    ref 'https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles?view=o365-worldwide#security-guidelines-for-assigning-roles'
    ref 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users'

    describe 'benchmark' do
        skip 'configure'
    end
end