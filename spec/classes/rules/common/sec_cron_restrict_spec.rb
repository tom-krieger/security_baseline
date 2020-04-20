require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_cron_restrict' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'cron' => {
                'restrict' => false,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'cron restrict',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file('/etc/cron.allow')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0600',
              )

            is_expected.to contain_file('/etc/cron.deny')
              .with(
                'ensure' => 'absent',
              )

            is_expected.to contain_file('/etc/at.allow')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0600',
              )

            is_expected.to contain_file('/etc/at.deny')
              .with(
                'ensure' => 'absent',
              )

            is_expected.not_to contain_echo('cron-restrict')
          else
            is_expected.not_to contain_file('/etc/cron.allow')
            is_expected.not_to contain_file('/etc/cron.deny')
            is_expected.not_to contain_file('/etc/at.allow')
            is_expected.not_to contain_file('/etc/at.deny')
            is_expected.to contain_echo('cron-restrict')
              .with(
                'message'  => 'cron restrict',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
