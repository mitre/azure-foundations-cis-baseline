control 'azure-foundations-cis-5.1.7' do
  title 'Ensure Public Network Access is Disabled'
  desc 'Disabling public network access restricts the service from accessing public networks.'

  desc 'rationale',
       'A secure network architecture requires carefully constructed network segmentation. Public Network Access tends to be overly permissive and introduces unintended vectors for threat activity.'

  desc 'impact',
       'Some architectural consideration may be necessary to ensure that required network connectivity is still made available. No additional cost or performance impact is required to deploy this recommendation.'

  desc 'check',
       "From Azure Portal
        1. Go to SQL servers.
        2. For each SQL server, under Security, click Networking.
        3. Ensure that Public network access is set to Disable."

  desc 'fix',
       "From Azure Portal
        1. Go to SQL servers.
        2. For each SQL server, under Security, click Networking.
        3. Set Public network access to Disable.
        4. Click Save."

  impact 0.5
  tag nist: ['CA-9', 'SC-7', 'SC-7(5)']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['4.4'] }]

  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-network-security#ns-2-secure-cloud-services-with-network-controls'
  ref 'https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings?view=azuresql&tabs=azure-portal#deny-public-network-access'

  servers_script = 'Get-AzSqlServer | ConvertTo-Json -Depth 10'
  servers_output = powershell(servers_script).stdout.strip
  all_servers = json(content: servers_output).params

  only_if('N/A - No Azure SQL Databases found', impact: 0) do
    case all_servers
    when Array
      !all_servers.empty?
    when Hash
      !all_servers.empty?
    else
      false
    end
  end

  describe 'Ensure Public Network Access is Disabled' do
    skip 'The check for this control needs to be done manually'
  end
end
