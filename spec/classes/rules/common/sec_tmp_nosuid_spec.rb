require 'spec_helper'

describe 'security_baseline::rules::common::sec_tmp_nosuid' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'partitions' => {
              'tmp' => {
                'nodev' => false,
                'noexec' => false,
                'nosuid' => false,
                'partition' => '/tmp',
              },
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'tmp nosuid',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('tmp-nosuid')
          .with(
            'message'  => 'tmp nosuid',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
