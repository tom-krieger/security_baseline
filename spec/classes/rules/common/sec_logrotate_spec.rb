require 'spec_helper'

describe 'security_baseline::rules::common::sec_logrotate' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }
    end
  end
end
enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_logrotate' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'packages_installed' => {
                'logrotate' => false,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'logrotate configuration',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to create_class('logrotate')
              .with(
                'config' => {
                  'dateext'      => true,
                  'compress'     => true,
                  'rotate'       => 7,
                  'rotate_every' => 'week',
                  'ifempty'      => true,
                },
              )
            is_expected.not_to contain_echo('logrotate')
          else
            is_expected.not_to create_class('logrotate')
            is_expected.to contain_echo('logrotate')
              .with(
                'message'  => 'logrotate configuration',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
