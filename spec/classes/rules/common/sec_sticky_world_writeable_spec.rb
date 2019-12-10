require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_sticky_world_writeable' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'sticky_ww' => 'available',
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'sticky bit world writable',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_exec("df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null|xargs chmod a+t")
              .with(
                'path' => '/bin/',
              )

            is_expected.not_to contain_echo('sticky-ww')
          else
            is_expected.not_to contain_exec("df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null|xargs chmod a+t")
            is_expected.to contain_echo('sticky-ww')
              .with(
                'message'  => 'sticky bit world writable',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
