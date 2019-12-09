require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_yum_gpgcheck' do
  enforce_options.each do |enforce|
    context "Redhat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          security_baseline: {
            yum: {
              gpgcheck: false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'yum gpgcheck option',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_file_line('yum_gpgcheck')
            .with(
              'ensure' => 'present',
              'path'   => '/etc/yum.conf',
              'line'   => 'gpgcheck=1',
              'match'  => '^gpgcheck',
            )

          is_expected.not_to contain_echo('yum_gpgcheck')
        else
          is_expected.not_to contain_file_line('yum_gpgcheck')
          is_expected.to contain_echo('yum_gpgcheck')
            .with(
              'message'  => 'yum gpgcheck option',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
