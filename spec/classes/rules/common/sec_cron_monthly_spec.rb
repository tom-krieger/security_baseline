require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_cron_monthly' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'cron' => {
                '/etc/cron.monthly' => {
                  'uid' => 0,
                  'gid' => 100,
                  'mode' => '0666',
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'cron monthly',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file('/etc/cron.monthly')
              .with(
                'ensure' => 'directory',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0700',
              )
            is_expected.not_to contain_echo('etc-cron-monthly')
          else
            is_expected.not_to contain_file('/etc/cron.monthly')
            is_expected.to contain_echo('etc-cron-monthly')
              .with(
                'message'  => 'cron monthly',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
