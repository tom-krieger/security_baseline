require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_aide_cron' do

  enforce_options.each do |enforce|

    on_supported_os.each do |os, os_facts|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'aide' => {
                'version' =>  '6.1.2',
                'status' => 'installed',
              }
            }
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'aide cron',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file('/etc/cron.d/aide.cron')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )
          else
            is_expected.to contain_echo('aide-cron')
              .with(
                'message'  => 'aide cron',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
