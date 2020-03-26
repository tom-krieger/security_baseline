require 'spec_helper_acceptance'
require 'pp'

ppc = <<-PUPPETCODE
$facts['security_baseline'] = loadjson('/tmp/default.json')
include security_baseline
PUPPETCODE

describe 'Security baseline' do
  context 'evaluating custom fact scripts' do
    it 'exit code should be 0' do
      expect(run_fact['exit_code']).to eq(0)
    end
  end

  # apply puppet module, custom facts not available
  context 'use CentOS 7 hiera data new' do
    it do
      idempotent_apply(ppc)
    end
  end
end
