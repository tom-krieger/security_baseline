# frozen_string_literal: true

require 'puppet_litmus'
require 'spec_helper_acceptance_local' if File.file?(File.join(File.dirname(__FILE__), 'spec_helper_acceptance_local.rb'))
require 'hiera-puppet-helper'

include PuppetLitmus
PuppetLitmus.configure!

puts 'own config'
fixture_path = File.expand_path(File.join(__FILE__, '..', 'fixtures'))

shared_context 'hieradata' do
  let(:hiera_config) do
    { backends: ['rspec', 'yaml'],
      hierarchy: [
        '%{fqdn}/%{calling_module}',
        '%{calling_module}',
        'common.yaml',
      ],
      yaml: {
        datadir: File.join(fixture_path, 'data'),
      },
      rspec: respond_to?(:hiera_data) ? hiera_data : {} }
  end
end
