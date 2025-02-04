control 'azure-foundations-cis-2.2.1' do
    title "Ensure That Microsoft Defender for IoT Hub Is Set To 'On'"
    desc "Microsoft Defender for IoT acts as a central security hub for IoT devices within your organization."

    desc 'rationale',
        "IoT devices are very rarely patched and can be potential attack vectors for enterprise
        networks. Updating their network configuration to use a central security hub allows for
        detection of these breaches."

    desc 'impact',
        "Enabling Microsoft Defender for IoT will incur additional charges dependent on the level of usage."

    desc 'check',
       "From Azure Portal
        1. Go to IoT Hub.
        2. Select a IoT Hub to validate.
        3. Select Overview in Defender for IoT.
        4. The Threat prevention and Threat detection screen will appear, if Defender for
        IoT is Enabled."

    desc 'fix',
       "From Azure Portal
        1. Go to IoT Hub.
        2. Select a IoT Hub to validate.
        3. Select Overview in Defender for IoT.
        4. Click on Secure your IoT solution, and complete the onboarding."

    impact 0.5
    tag nist: ['RA-5','SI-4','SI-4(4)']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['7.5', '13.6'] }]

    ref 'https://azure.microsoft.com/en-us/services/iot-defender/#overview'
    ref 'https://docs.microsoft.com/en-us/azure/defender-for-iot/'
    ref 'https://azure.microsoft.com/en-us/pricing/details/iot-defender/'
    ref 'https://docs.microsoft.com/en-us/security/benchmark/azure/baselines/defender-for-iot-security-baseline'
    ref 'https://docs.microsoft.com/en-us/cli/azure/iot?view=azure-cli-latest'
    ref 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities'
    ref 'https://learn.microsoft.com/en-us/azure/defender-for-iot/device-builders/quickstart-onboard-iot-hub'

    describe "Ensure That Microsoft Defender for IoT Hub Is Set To 'On'" do
        skip 'The check for this control needs to be done manually'
    end
end