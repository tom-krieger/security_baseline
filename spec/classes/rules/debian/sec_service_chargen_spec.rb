require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_service_chargen' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            inetd_services: {
              srv_chargen: {
                status: true,
                filename: '/etc/xinetd.d/chargen',
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'service chargen',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_file_line('chargen_disable')
            .with(
              'line'     => 'disable     = yes',
              'path'     => '/etc/xinetd.d/chargen',
              'match'    => 'disable.*=',
              'multiple' => true,
            )

          is_expected.not_to contain_echo('chargen-inetd')
        else
          is_expected.not_to contain_service('chargen_disable')
          is_expected.to contain_echo('chargen-inetd')
            .with(
              'message'  => 'service chargen',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
