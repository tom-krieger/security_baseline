require 'spec_helper'

describe 'security_baseline::rules::common::sec_empty_passwords' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }
    end
  end
end
enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_empty_passwords' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
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
            'enforce' => enforce,
            'message' => 'empty passwords',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.not_to contain_echo('empty-passwords')
          else
            is_expected.to contain_echo('empty-passwords')
              .with(
                'message'  => 'empty passwords',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
