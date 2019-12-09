require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_zypper_gpgcheck' do
  enforce_options.each do |enforce|
    context "Suse with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Suse',
          operatingsystem: 'SLES',
          architecture: 'x86_64',
          security_baseline: {
            zypper: {
              gpgcheck: false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'zypper gpgcheck option',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_file_line('zypper_gpgcheck')
            .with(
              'ensure' => 'present',
              'path'   => '/etc/zypp/zypp.conf',
              'line'   => 'gpgcheck = on',
              'match'  => '^gpgcheck',
            )

          is_expected.not_to contain_echo('zypper_gpgcheck')
        else
          is_expected.not_to contain_file_line('zypper_gpgcheck')
          is_expected.to contain_echo('zypper_gpgcheck')
            .with(
              'message'  => 'zypper gpgcheck option',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
