control 'azure-foundations-cis-9.2' do
  title 'Ensure App Service Authentication is set up for apps in Azure App Service'
  desc 'Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching a Web Application or authenticate those with tokens before they reach the app. If an anonymous request is received from a browser, App Service will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented.'

  desc 'rationale',
       'By Enabling App Service Authentication, every incoming HTTP request passes through it before being handled by the application code. It also handles authentication of users with the specified provider (Entra ID, Facebook, Google, Microsoft Account, and Twitter), validation, storing and refreshing of tokens, managing the authenticated sessions and injecting identity information into request headers. Disabling HTTP Basic Authentication functionality further ensures legacy authentication methods are disabled within the application.'

  desc 'impact',
       'This is only required for App Services which require authentication. Enabling on site like a marketing or support website will prevent unauthenticated access which would be undesirable.
        Adding Authentication requirement will increase cost of App Service and require additional security components to facilitate the authentication.'

  desc 'check',
       "Audit from Azure Portal
            1. Login to Azure Portal using https://portal.azure.com
            2. Go to App Services
            3. Click on each App
            4. Under Settings section, Click on Authentication
            5. Ensure that App Service authentication set to Enabled (Will only appear once an Identity provider is set up/selected)
            6. Navigate back to the application blade
            7. Under Settings, click on Configuration
            8. Click on the 'General Settings' tab
            9. Under Platform settings, ensure Basic Auth Publishing Credentials is set to Off
        Audit from Azure CLI
            To check App Service Authentication status for an existing app, run the following command (using authV1 extension),
                az webapp auth show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME>
            The output should return true if App Service authentication is set to On. If using the authV2 extension for the az webapp auth CLI, run the following command,
                az webapp auth show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME>
            Ensure that the enabled setting under azureActiveDirectory is set to true. To check whether the Basic Auth Publishing Credentials are disabled, issue the following commands,
                az resource show --resource-group <RESOURCE GROUP NAME> --name scm --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies --parent sites/<APPLICATION NAME>
                az resource show --resource-group <RESOURCE GROUP NAME> --name ftp --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies --parent sites/<APPLICATION NAME>
                Ensure allow is set to false under properties within the output of each of the above commands.
        Audit from Azure Policy
            If referencing a digital copy of this Benchmark, clicking a Policy ID will open a link to the associated Policy definition in Azure. If referencing a printed copy, you can search Policy IDs from this URL: https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Definitions
                • Policy ID: c75248c1-ea1d-4a9c-8fc9-29a6aabd5da8 - Name: 'Function apps should have authentication enabled'
                • Policy ID: 95bccee9-a7f8-4bec-9ee9-62c3473701fc - Name: 'App Service apps should have authentication enabled'"

  desc 'fix',
       "Remediate from Azure Portal
                1. Login to Azure Portal using https://portal.azure.com
                2. Go to App Services
                3. Click on each App
                4. Under Setting section, click on Authentication
                5. If no identity providers are set up, then click Add identity provider
                6. Choose other parameters as per your requirements and click on Add
            To disable the Basic Auth Publishing Credentials setting, perform the following steps:
                1. Login to Azure Portal using https://portal.azure.com
                2. Go to App Services
                3. Click on each App
                4. Under Settings, click on Configuration
                5. Click on the 'General Settings' tab
                6. Under Platform settings, ensure Basic Auth Publishing Credentials is set to Off
        Remediate from Azure CLI
            To set App Service Authentication for an existing app, run the following command:
                az webapp auth update --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --enabled true
            Note: In order to access App Service authentication settings for Web app using Microsoft API requires Website contributor permission at subscription level. A custom role can be created in place of Website contributor to provide more specific permission and maintain the principle of least privileged access."

  impact 0.5
  tag nist: ['AC-3', 'AC-5', 'AC-6', 'MP-2']
  tag severity: 'medium'
  tag cis_controls: [{ '8' => ['3.3'] }]

  ref 'https://docs.microsoft.com/en-us/azure/app-service/app-service-authentication-overview'
  ref 'https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#website-contributor'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements'
  ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy'

  app_script = 'Get-AzKeyVault | ConvertTo-Json -Depth 10'
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

  rg_an_list = input('resource_group_and_app_name')

  rg_an_list.each do |pair|
    resource_group, app_name = pair.split('.')
    enabled_info = command("az webapp auth show --resource-group #{resource_group} --name #{app_name} --query enabled")
    scm_info = command("az resource show --resource-group #{resource_group} --name scm --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies --parent sites/#{app_name} --query properties.allow")
    ftp_info = command("az resource show --resource-group #{resource_group} --name ftp --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies --parent sites/#{app_name} --query properties.allow")
    describe "Application Name '#{app_name}' in Resource Group '#{resource_group}'" do
      describe 'App Service Authentication setting' do
        subject { enabled_info.stdout.strip }
        it "should be set to 'true'" do
          expect(subject).to cmp(true)
        end
      end

      describe 'Properties.allow setting for SCM Basic Auth Publishing Credentials' do
        subject { scm_info.stdout.strip }
        it "should be set 'false'" do
          expect(subject).to cmp(false)
        end
      end

      describe 'Properties.allow setting for SCM Basic Auth Publishing Credentials' do
        subject { ftp_info.stdout.strip }
        it "should be set 'false'" do
          expect(subject).to cmp(false)
        end
      end
    end
  end
end
