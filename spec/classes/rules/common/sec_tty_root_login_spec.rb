require 'spec_helper'

describe 'security_baseline::rules::common::sec_tty_root_login' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'enforce' => true,
          'message' => 'root console login',
          'log_level' => 'info',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('root-tty-console')
          .with(
            'message'  => 'root console login',
            'loglevel' => 'info',
            'withpath' => false,
          )
      }
    end
  end
end
