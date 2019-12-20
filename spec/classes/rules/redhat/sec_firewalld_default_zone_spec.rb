require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_firewalld_default_zone' do
  enforce_options.each do |enforce|
    context "RedHat with enforce #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'security_baseline' => {
            'firewalld' => {
              'default_zone' => 'private',
              'default_zone_status' => false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'firewalld default zone',
          'log_level' => 'warning',
          'default_zone' => 'public',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('set firewalld default zone')
            .with(
              'command' => 'firewall-cmd --set-default-zone=public',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )

          is_expected.not_to contain_echo('firewalld-default-zone')
        else
          is_expected.not_to contain_exec('set firewalld default zone')
          is_expected.to contain_echo('firewalld-default-zone')
            .with(
              'message'  => 'firewalld default zone',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
