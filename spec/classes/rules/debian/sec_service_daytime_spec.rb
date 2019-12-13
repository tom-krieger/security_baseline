require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_service_daytime' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            inetd_services: {
              srv_daytime: {
                status: true,
                filename: '/etc/xinetd.d/daytime',
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'service daytime',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_file_line('daytime_disable')
          .with(
            'line'     => 'disable     = yes',
            'path'     => '/etc/xinetd.d/daytime',
            'match'    => 'disable.*=',
            'multiple' => true,
          )

          is_expected.not_to contain_echo('daytime-inetd')
        else
          is_expected.not_to contain_service('daytime_disable')
          is_expected.to contain_echo('daytime-inetd')
            .with(
              'message'  => 'service daytime',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
