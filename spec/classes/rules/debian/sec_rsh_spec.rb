require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_rsh' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            inetd_services: {
              srv_rsh: {
                status: true,
                filename: '/etc/xinetd.d/rsh',
              },
              srv_rlogin: {
                status: true,
                filename: '/etc/xinetd.d/rsh',
              },
              srv_rexec: {
                status: true,
                filename: '/etc/xinetd.d/rsh',
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'rsh service',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_file_line('rsh_disable')
            .with(
              'line'     => 'disable     = yes',
              'path'     => '/etc/xinetd.d/rsh',
              'match'    => 'disable.*=',
              'multiple' => true,
            )

          is_expected.to contain_file_line('rlogin_disable')
            .with(
              'line'     => 'disable     = yes',
              'path'     => '/etc/xinetd.d/rsh',
              'match'    => 'disable.*=',
              'multiple' => true,
            )

          is_expected.to contain_file_line('rexec_disable')
            .with(
              'line'     => 'disable     = yes',
              'path'     => '/etc/xinetd.d/rsh',
              'match'    => 'disable.*=',
              'multiple' => true,
            )
          is_expected.not_to contain_echo('rsh-service')
        else
          is_expected.not_to contain_file_line('rsh_disable')
          is_expected.not_to contain_file_line('rlogin_disable')
          is_expected.not_to contain_file_line('rexec_disable')
          is_expected.to contain_echo('rsh-service')
            .with(
              'message'  => 'rsh service',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
