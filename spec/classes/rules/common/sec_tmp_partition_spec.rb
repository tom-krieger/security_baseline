require 'spec_helper'

describe 'security_baseline::rules::common::sec_tmp_partition' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'home_dir_permissions' => 'xyz',
            'partitions' => {
              'tmp' => {
                'nodev' => false,
                'noexec' => false,
                'nosuid' => false,
              },
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'tmp partition',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('tmp-partition')
          .with(
            'message'  => 'tmp partition',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
