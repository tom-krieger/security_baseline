require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_empty_passwords' do
  on_supported_os.each do |os, os_facts|
    context "on #{os} with enforce = #{enforce}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'empty_passwords' => '123456',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'empty passwords',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('empty-passwords')
          .with(
            'message'  => 'empty passwords',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
