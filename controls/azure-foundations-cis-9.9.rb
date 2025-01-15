control 'azure-foundations-cis-1.1.1' do
    title "title"
    desc "description"

    desc 'rationale',
        "description"

    desc 'check',
       "description"

    desc 'fix',
       "description"

    

    impact 0.5
    tag nist: ['tag']
    tag severity: 'medium'
    tag cis_controls: [{ '8' => ['control'] }]

    describe 'benchmark' do
        skip 'configure'
    end
end