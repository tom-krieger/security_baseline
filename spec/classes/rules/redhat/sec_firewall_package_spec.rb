require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_firewall_package' do
  enforce_options.each do |enforce|
    context "RedHat with enforce #{enforce} and firewalld" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemrelease: '8',
          architecture: 'x86_64',
          kernel: 'Linux',
          'security_baseline' => {
            'packages_installed' => {
              'firewalld' => false,
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
          'firewall_package' => 'firewalld',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_package('firewalld')
            .with(
              'ensure' => 'installed',
            )
          is_expected.not_to contain_echo('firewall-package')
        else
          is_expected.not_to contain_package('firewalld')
          is_expected.to contain_echo('firewall-package')
            .with(
              'message'  => 'firewall package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end

    context "RedHat with enforce #{enforce} and nftables" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemrelease: '8',
          architecture: 'x86_64',
          kernel: 'Linux',
          'security_baseline' => {
            'packages_installed' => {
              'firewalld' => false,
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

    context "RedHat with enforce #{enforce} and iptables" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemrelease: '8',
          architecture: 'x86_64',
          kernel: 'Linux',
          'security_baseline' => {
            'packages_installed' => {
              'firewalld' => false,
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
          is_expected.to contain_package('iptables')
            .with(
              'ensure' => 'installed',
            )
          is_expected.not_to contain_echo('firewall-package')
        else
          is_expected.not_to contain_package('iptables')
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
