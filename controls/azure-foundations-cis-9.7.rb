control 'azure-foundations-cis-9.7' do
    title "Ensure that 'PHP version' is currently supported (if in use)"
    desc "Periodically, older versions of PHP may be deprecated and no longer supported. Using a supported version of PHP for app services is recommended to avoid potential unpatched vulnerabilities."

    desc 'rationale',
        "Deprecated and unsupported versions of programming and scripting languages can present vulnerabilities which may not be addressed or may not be addressable."

    desc 'impact',
        'If your app is written using version-dependent features or libraries, they may not be available on more recent versions. If you wish to update, research the impact thoroughly.'
        
    desc 'check',
       %(Audit from Azure Portal
            1. From Azure Home open the Portal Menu in the top left
            2. Go to App Services
            3. Click on each App
            4. Under Settings section, click on Configuration
            5. Click on the General settings pane, ensure that for a Stack of PHP the Major Version and Minor Version reflect the latest stable and supported release.
        ** The latest stable version can be confirmed by going to php.net. Navigate to the downloads, and then find the most recent version that is marked by Current Stable PHP [version_number]. ** NOTE: No action is required If PHP version is set to Off as PHP is not used by your web app.
        Audit from Azure CLI 
            To check PHP version for an existing app, run the following command,
                az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query "{LinuxFxVersion:linuxFxVersion,PHP_Version:phpVersion}"
        Audit From Powershell 
            $application = Get-AzWebApp -ResourceGroupName <resource group name> -Name <app name> 
            $application.SiteConfig | select-object LinuxFXVersion, phpVersion
            The output should return the latest available version of PHP. Any other version of PHP would be considered a finding. NOTE: No action is required, If the output is empty as PHP is not used by your web app.
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
            • Policy ID: f466b2a6-823d-470d-8ea5-b031e72d79ae - Name: 'App Service app slots that use PHP should use a specified 'PHP version''
            • Policy ID: 7261b898-8a84-4db8-9e04-18527132abb3 - Name: 'App Service apps that use PHP should use a specified 'PHP version'')

    desc 'fix',
       "Remediate from Azure Portal
            1. From Azure Home open the Portal Menu in the top left
            2. Go to App Services
            3. Click on each App
            4. Under Settings section, click on Configuration
            5. Click on the General settings pane, ensure that for a Stack of PHP the Major Version and Minor Version reflect the latest stable and supported release.
        NOTE: No action is required If PHP version is set to Off or is set with an empty value as PHP is not used by your web app.
        Remediate from Azure CLI 
            List the available PHP runtimes: 
                az webapp list-runtimes
            To set latest PHP version for an existing app, run the following command: 
                az webapp config set --resource-group <resource group name> --name <app name> [--linux-fx-version <php runtime version>][--php-version <php version>]
        Remediate From Powershell 
            To set latest PHP version for an existing app, run the following command: 
                Set-AzWebApp -ResourceGroupName <resource group name> -Name <app name> -phpVersion <php version>
        NOTE: Currently there is no way to update an existing web app Linux FX Version setting using PowerShell, nor is there a way to create a new web app using PowerShell that configures the PHP runtime in the Linux FX Version setting."

    impact 0.5
    tag nist: ['SA-22']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['2.2'] }]

    ref 'https://docs.microsoft.com/en-us/azure/app-service/web-sites-configure#general-settings'
    ref 'https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-posture-vulnerability-management#pv-7-rapidly-and-automatically-remediate-software-vulnerabilities'
    ref 'https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-posture-vulnerability-management#pv-3-establish-secure-configurations-for-compute-resources'
    ref 'https://www.php.net/supported-versions.php'

    describe 'benchmark' do
        skip 'configure'
    end
end