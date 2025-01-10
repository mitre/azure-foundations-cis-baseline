control 'azure-foundations-cis-1.1.1' do
    title 'Ensure Trusted Locations Are Defined'
    desc "Microsoft Entra ID Conditional Access allows an organization to configure Named
        locations and configure whether those locations are trusted or untrusted. These
        settings provide organizations the means to specify Geographical locations for use in
        conditional access policies, or define actual IP addresses and IP ranges and whether or
        not those IP addresses and/or ranges are trusted by the organization."

    desc 'rationale',
        "Defining trusted source IP addresses or ranges helps organizations create and enforce
        Conditional Access policies around those trusted or untrusted IP addresses and ranges.
        Users authenticating from trusted IP addresses and/or ranges may have less access
        restrictions or access requirements when compared to users that try to authenticate to
        Microsoft Entra ID from untrusted locations or untrusted source IP addresses/ranges."

    desc 'impact',
        "When configuring Named locations, the organization can create locations using
        Geographical location data or by defining source IP addresses or ranges. Configuring
        Named locations using a Country location does not provide the organization the ability
        to mark those locations as trusted, and any Conditional Access policy relying on those
        Countries location setting will not be able to use the All trusted locations setting
        within the Conditional Access policy. They instead will have to rely on the Select
        locations setting. This may add additional resource requirements when configuring,
        and will require thorough organizational testing.
        In general, Conditional Access policies may completely prevent users from
        authenticating to Microsoft Entra ID, and thorough testing is recommended. To avoid
        complete lockout, a 'Break Glass' account with full Global Administrator rights is
        recommended in the event all other administrators are locked out of authenticating to
        Microsoft Entra ID. This 'Break Glass' account should be excluded from Conditional
        Access Policies and should be configured with the longest pass phrase feasible. This
        account should only be used in the event of an emergency and complete administrator
        lockout."

    desc 'check',
       "From Azure Portal
        1. In the Azure Portal, navigate to Microsoft Entra ID Conditional Access
        2. Click on Manage
        3. Click on Named Locations
        Page 34
        Ensure there are IP ranges location settings configured and marked as Trusted
        From PowerShell
        Get-AzureADMSNamedLocationPolicy
        In the output from the above command, for each Named location group, make sure at
        least one entry contains the IsTrusted parameter with a value of True. Otherwise, if
        there is no output as a result of the above command or all of the entries contain the
        IsTrusted parameter with an empty value, a NULL value, or a value of False, the results
        are out of compliance with this check."

    desc 'fix',
       "From Azure Portal
        1. Navigate to the Microsoft Entra ID Conditional Access Blade
        2. Click on the Named locations blade
        3. Within the Named locations blade, click on IP ranges location
        4. Enter a name for this location setting in the Name text box
        5. Click on the + sign
        6. Add an IP Address Range in CIDR notation inside the text box that appears
        7. Click on the Add button
        8. Repeat steps 5 through 7 for each IP Range that needs to be added
        9. If the information entered are trusted ranges, select the Mark as trusted
        location check box
        10. Once finished, click on Create
        From PowerShell
        Create a new trusted IP-based Named location policy
        [System.Collections.Generic.List`1[Microsoft.Open.MSGraph.Model.IpRange]]$ipR
        anges = @()
        $ipRanges.Add('<first IP range in CIDR notation>')
        $ipRanges.Add('<second IP range in CIDR notation>')
        $ipRanges.Add('<third IP range in CIDR notation>')
        New-AzureADMSNamedLocationPolicy -OdataType
        '#microsoft.graph.ipNamedLocation' -DisplayName '<name of IP Named location
        policy> -IsTrusted $true -IpRanges $ipRanges
        Set an existing IP-based Named location policy to trusted
        Set-AzureADMSNamedLocationPolicy -PolicyId '<ID of the policy>' -OdataType
        '#microsoft.graph.ipNamedLocation' -IsTrusted $true"

    impact 0.5
    tag nist: ['check NIST SP 800-53, Revision 5']
    tag severity: 'low, medium, or high '
    tag cis_controls: [{ '8.1' => ['check cis controls navigator'] }]

    ref 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/location-condition'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-7-restrict-resource-access-based-on--conditions'

    describe 'benchmark' do
        skip 'configure'
    end
end