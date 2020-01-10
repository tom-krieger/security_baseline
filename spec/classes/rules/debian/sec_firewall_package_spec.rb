require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_firewall_package' do
  enforce_options.each do |enforce|
    context "Debin with enforce #{enforce} and ufw" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          operatingsystemrelease: '18',
          architecture: 'x86_64',
          kernel: 'Linux',
          selinux: true,
          'security_baseline' => {
            'packages_installed' => {
              'ufw' => false,
              'nftables' => false,
              'iptables' => false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'firewall package',
          'log_level' => 'warning',
          'firewall_package' => 'ufw',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_package('ufw')
            .with(
              'ensure' => 'installed',
            )
          is_expected.not_to contain_echo('firewall-package')
        else
          is_expected.not_to contain_package('ufw')
          is_expected.to contain_echo('firewall-package')
            .with(
              'message'  => 'firewall package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end

    context "Debian with enforce #{enforce} and nftables" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemrelease: '8',
          architecture: 'x86_64',
          kernel: 'Linux',
          selinux: true,
          'security_baseline' => {
            'packages_installed' => {
              'ufw' => false,
              'nftables' => false,
              'iptables' => false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'firewall package',
          'log_level' => 'warning',
          'firewall_package' => 'nftables',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_package('nftables')
            .with(
              'ensure' => 'installed',
            )
          is_expected.not_to contain_echo('firewall-package')
        else
          is_expected.not_to contain_package('nftables')
          is_expected.to contain_echo('firewall-package')
            .with(
              'message'  => 'firewall package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end

    context "Debian with enforce #{enforce} and iptables" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemrelease: '8',
          architecture: 'x86_64',
          kernel: 'Linux',
          selinux: true,
          'security_baseline' => {
            'packages_installed' => {
              'ufw' => false,
              'nftables' => false,
              'iptables' => false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'firewall package',
          'log_level' => 'warning',
          'firewall_package' => 'iptables',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_class('firewall')
          is_expected.not_to contain_echo('firewall-package')
        else
          is_expected.not_to contain_class('firewall')
          is_expected.to contain_echo('firewall-package')
            .with(
              'message'  => 'firewall package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
