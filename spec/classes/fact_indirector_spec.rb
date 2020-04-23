# frozen_string_literal: true

require 'spec_helper'

describe 'security_baseline::fact_indirector' do
  on_supported_os.each do |os, os_facts|
    context "on #{os} configure logstash facts indirector" do
      let(:facts) do
        os_facts.merge(
          'is_pe' => true,
        )
      end
      let(:params) do
        {
          'logstash_host' => '1.2.3.4',
          'logstash_port' => 5999,
          'logstash_timeout' => 1000,
          'configure_logstash' => true,
        }
      end
      let(:pre_condition) do
        <<-EOF
        service { 'pe-puppetserver':
          ensure => 'running',
          enable => true,
        }
        EOF
      end

      it {
        is_expected.to compile
        is_expected.to contain_file('/etc/puppetlabs/puppet/security_baseline.yaml')
          .with(
            'ensure'  => 'file',
            'owner'   => 'pe-puppet',
            'group'   => 'pe-puppet',
            'mode'    => '0644',
          )
        is_expected.to contain_file('/etc/puppetlabs/puppet/security_baseline_routes.yaml')
          .with(
            'ensure'  => 'file',
            'owner'   => 'pe-puppet',
            'group'   => 'pe-puppet',
            'mode'    => '0640',
          )
        is_expected.to contain_ini_setting('enable security_baseline_routes.yaml')
          .with(
            'ensure'  => 'present',
            'path'    => '/etc/puppetlabs/puppet/puppet.conf',
            'section' => 'master',
            'setting' => 'route_file',
            'value'   => '/etc/puppetlabs/puppet/security_baseline_routes.yaml',
          )
          .that_notifies('Service[pe-puppetserver]')
          .that_requires('File[/etc/puppetlabs/puppet/security_baseline_routes.yaml]')
      }
    end
  end
end
