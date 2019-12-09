require 'spec_helper'

describe 'security_baseline::rules::common::sec_root_path_integrity' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'root_path_integrity' => 'root',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'root path integrity',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_echo('root-path-integrity')
          .with(
            'message'  => 'root path integrity',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      end
    end
  end
end
