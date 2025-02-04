control 'azure-foundations-cis-9.9' do
    title "Ensure that 'Java version' is currently supported (if in use)"
    desc "Periodically, older versions of Java may be deprecated and no longer supported. Using a supported version of Java for app services is recommended to avoid potential unpatched vulnerabilities."

    desc 'rationale',
        "Deprecated and unsupported versions of programming and scripting languages can present vulnerabilities which may not be addressed or may not be addressable."

    desc 'impact',
        'If your app is written using version-dependent features or libraries, they may not be available on more recent versions. If you wish to update, research the impact thoroughly.'

    desc 'check',
       %(Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com
            2. Go to App Services
            3. Click on each App
            4. Under Settings section, click on Configuration
            5. Click on the General settings pane and ensure that for a Stack of Java the Major Version and Minor Version reflect the latest stable and supported release, and that the Java web server version is set to the auto-update option.
        NOTE: No action is required if Java version is set to Off, as Java is not used by your web app.
        Audit from Azure CLI 
            To check Java version for an existing app, run the following command,
                az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query "{LinuxFxVersion:linuxFxVersion, WindowsFxVersion:windowsFxVersion, JavaVersion:javaVersion, JavaContainerVersion:javaContainerVersion, JavaContainer:javaContainer}"
            The output should return the latest available version of Java (if java is being used for the web application being audited).
        Audit From Powershell 
            For each application, store the application information within an object, and then interrogate the SiteConfig information for that application object. 
                $app = Get-AzWebApp -Name <app name> -ResourceGroup <resource group name> 
                $app.SiteConfig |Select-Object LinuxFXVersion, WindowsFxVersion, JavaVersion, JavaContainerVersion, JavaContainer
            Ensure the Java version used within the application is a currently supported version (if java is being used for the web application being audited).
        Audit from Azure Policy 
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: e1d1b522-02b0-4d18-a04f-5ab62d20445f - Name: 'Function app slots that use Java should use a specified 'Java version''
                • Policy ID: 9d0b6ea4-93e2-4578-bf2f-6bb17d22b4bc - Name: 'Function apps that use Java should use a specified 'Java version'')

    desc 'fix',
       %(Remediate from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com
            2. Go to App Services
            3. Click on each App
            4. Under Settings section, click on Configuration
            5. Click on the General settings pane and ensure that for a Stack of Java the Major Version and Minor Version reflect the latest stable and supported release, and that the Java web server version is set to the auto-update option.
        NOTE: No action is required if Java version is set to Off, as Java is not used by your web app.
        Remediate from Azure CLI 
            To see the list of supported runtimes: 
                az webapp list-runtimes
            To set latest Java version for an existing app, run the following command: 
                az webapp config set --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> [--java-version <JAVA_VERSION> --java-container <JAVA_CONTAINER> --java-container-version <JAVA_CONTAINER_VERSION> [--windows-fx-version <java runtime version>] [--linux-fx-version <java runtime version version>]
            If creating a new web application to use a currently supported version of Java, run the following commands. 
                To create an app service plan: 
                    az appservice plan create --resource-group <resource group name> --name <plan name> --location <location> [--is-linux --number-of-workers <int> --sku <pricing tier>] [--hyper-v --sku <pricing tier>]
                Get the app service plan ID: 
                    az appservice plan list --query "[].{Name:name, ID:id, SKU:sku, Location:location}"
                To create a new Java web application using the retrieved app service ID: 
                    az webapp create --resource-group <resource group name> --plan <app service plan ID> --name <app name> [--linux-fx-version <java run time version>] [--windows-fx-version <java run time version>]
        Remediate From Powershell 
            As of this writing, there is no way to update an existing application's SiteConfig or set a new application's SiteConfig settings during creation via PowerShell.)

    impact 0.5
    tag nist: ['SA-22']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['2.2'] }]

    ref 'https://docs.microsoft.com/en-us/azure/app-service/web-sites-configure#general-settings'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-posture-vulnerability-management#pv-3-define-and-establish-secure-configurations-for-compute-resources'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-posture-vulnerability-management#pv-6-rapidly-and-automatically-remediate-vulnerabilities'
    ref 'https://www.oracle.com/java/technologies/java-se-support-roadmap.html'

    describe 'benchmark' do
        skip 'The check for this control needs to be done manually'
    end
end