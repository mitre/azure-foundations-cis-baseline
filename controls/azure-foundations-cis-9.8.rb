control 'azure-foundations-cis-9.8' do
  title "Ensure that 'Python version' is currently supported (if in use)"
  desc 'Periodically, older versions of Python may be deprecated and no longer supported. Using a supported version of Python for app services is recommended to avoid potential unpatched vulnerabilities.'

  desc 'rationale',
       'Deprecated and unsupported versions of programming and scripting languages can present vulnerabilities which may not be addressed or may not be addressable.'

  desc 'impact',
       'If your app is written using version-dependent features or libraries, they may not be available on more recent versions. If you wish to update, research the impact thoroughly.'

  desc 'check',
       %(
       Audit From Azure Portal
            1. From Azure Home open the Portal Menu in the top left
            2. Go to App Services
            3. Click on each App
            4. Under Settings section, click on Configuration
            5. Click on the General settings pane and ensure that for a Stack of Python, with Major Version of Python 3, that the Minor Version is set to the latest stable version available (Python 3.11, at the time of writing)
        NOTE: No action is required if Python version is set to Off, as Python is not used by your web app.
        Audit from Azure CLI
            To check Python version for an existing app, run the following command
                az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query "{LinuxFxVersion:linuxFxVersion,WindowsFxVersion:windowsFxVersion,PythonVersion:pythonVersion}
            The output should return the latest stable version of Python. NOTE: No action is required if the output is empty, as Python is not used by your web app.
        Audit From Powershell
            $app = Get-AzWebApp -Name <app name> -ResourceGroup <resource group name>
            $app.SiteConfig |Select-Object LinuxFXVersion, WindowsFxVersion, PythonVersion
            Ensure the output of the above command shows the latest version of Python. NOTE: No action is required if the output is empty, as Python is not used by your web app.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: 9c014953-ef68-4a98-82af-fd0f6b2306c8 - Name: 'App Service app slots that use Python should use a specified 'Python version''
                • Policy ID: 7008174a-fd10-4ef0-817e-fc820a951d73 - Name: 'App Service apps that use Python should use a specified 'Python version'')

  desc 'fix',
       %(Remediate from Azure Portal
            1. From Azure Home open the Portal Menu in the top left
            2. Go to App Services
            3. Click on each App
            4. Under Settings section, click on Configuration
            5. Click on the General settings pane and ensure that the Major Version and the Minor Version is set to the latest stable version available (Python 3.11, at the time of writing)
        NOTE: No action is required if Python version is set to Off, as Python is not used by your web app.
        Remediate from Azure CLI
            To see the list of supported runtimes:
                az webapp list-runtimes
            To set latest Python version for an existing app, run the following command:
                az webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> [--windows-fx-version "PYTHON|3.11"] [--linux-fx-version "PYTHON|3.11"]
        Remediate From Powershell
            As of this writing, there is no way to update an existing application's SiteConfig or set the a new application's SiteConfig settings during creation via PowerShell.)

  impact 0.5
  tag nist: ['SA-22']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['2.2'] }]

  ref 'https://docs.microsoft.com/en-us/azure/app-service/web-sites-configure#general-settings'
  ref 'https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-posture-vulnerability-management#pv-7-rapidly-and-automatically-remediate-software-vulnerabilities'
  ref 'https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-posture-vulnerability-management#pv-3-establish-secure-configurations-for-compute-resources'
  ref 'https://devguide.python.org/versions/'

  app_script = 'Get-AzKeyVault | ConvertTo-Json'
  app_output = powershell(app_script).stdout.strip
  all_apps = json(content: app_output).params

  only_if('N/A - No Web Applications found', impact: 0) do
    case all_apps
    when Array
      !all_apps.empty?
    when Hash
      !all_apps.empty?
    else
      false
    end
  end

  python_version_unsupported_web_app = input('python_version_unsupported_web_app')
  python_version_unsupported_web_app_list = python_version_unsupported_web_app.map { |python_version| "'#{python_version}'" }.join(', ')
  ensure_web_app_python_version_supported_script = %(
        $ErrorActionPreference = "Stop"
        $filteredWebApps = Get-AzWebApp | Select-Object ResourceGroup, Name
        $unsupported_python_versions = @(#{python_version_unsupported_web_app_list})
        foreach ($webApp in $filteredWebApps) {
            $resourceGroup = $webApp.ResourceGroup
            $appName = $webApp.Name

            # Get the SiteConfig for the current web app
            $application = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $appName
            $LinuxFxVersion = $application.SiteConfig.LinuxFXVersion
            $WindowsFxVersion = $application.SiteConfig.WindowsFxVersion
            $pythonVersionFromLinuxFxVersion = $null
            $pythonVersionFromWindowsFxVersion = $null

            # Check if LinuxFxVersion exists and extract Python version
            if ($LinuxFxVersion -ne $null -and $LinuxFxVersion.Trim() -ne "") {
                if ($LinuxFxVersion -like "Python|*") {
                    $pythonVersionFromLinuxFxVersion = ($LinuxFxVersion.Trim() -split '\\|')[1]
                }
            }

            # Check if WindowsFxVersion exists and extract Python version
            if ($WindowsFxVersion -ne $null -and $WindowsFxVersion.Trim() -ne "") {
                if ($WindowsFxVersion -like "Python|*") {
                    $pythonVersionFromWindowsFxVersion = ($WindowsFxVersion.Trim() -split '\\|')[1]
                }
            }

            # Check if either Python version is unsupported
            if ($unsupported_python_versions -contains $pythonVersionFromLinuxFxVersion -or $unsupported_python_versions -contains $pythonVersionFromWindowsFxVersion) {
                # Print the name of the web app
                Write-Output "$appName"
            }
        }
    )

  pwsh_output = powershell(ensure_web_app_python_version_supported_script)
  raise Inspec::Error, "The powershell output returned the following error:  #{pwsh_output.stderr}" if pwsh_output.exit_status != 0

  describe 'Ensure that the number of Web Applications/Resource Group combinations with unsupported SiteConfig.LinuxFXVersion for Python' do
    subject { pwsh_output.stdout.strip }
    it 'is 0' do
      failure_message = "The following web apps have an unsupported version of Python: #{pwsh_output.stdout.strip}"
      expect(subject).to be_empty, failure_message
    end
  end
end
