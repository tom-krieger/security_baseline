require 'puppet'
require 'puppet/util'
require 'puppet/node/facts'
require 'puppet/network/http_pool'
require 'fileutils'
require 'net/http'
require 'net/https'
require 'uri'
require 'yaml'
require 'json'
require 'time'
require 'timeout'

# Utility functions used by the report processor and the facts indirector.
module Puppet::Util::SecurityBaseline
  def settings
    return @settings if @settings
    @settings_file = Puppet[:confdir] + '/security_baseline.yaml'
    @settings = YAML.load_file(@settings_file)
  end

  def pe_console
    settings['pe_console'] || Puppet[:certname]
  end

  def security_baseline_fact_server
    settings[:host]
  end

  def security_baseline_fact_server_port
    settings[:port]
  end

  def security_baseline_fact_timeout
    settings[:timeout]
  end

  def get_trusted_info(node)
    trusted = Puppet.lookup(:trusted_information) do
      Puppet::Context::TrustedInformation.local(node)
    end
    trusted.to_h
  end

  def send_facts(request, time)
    # Copied from the puppetdb fact indirector.  Explicitly strips
    # out the packages custom fact '_puppet_inventory_1'
    facts = request.instance.dup
    facts.values = facts.values.dup

    return unless facts.values.key?('security_baseline_summary')

    facts.values[:trusted] = get_trusted_info(request.node)

    # Puppet.info "Facts of security_baseline: #{facts.values[:trusted].to_json} |"

    facts.values.delete('_puppet_inventory_1')
    facts.values = facts.values.dup

    data = {}
    data['@timestamp'] = time
    data['key'] = request.key
    data['environment'] = request.options[:environment] || request.environment.to_s
    data['tags'] = ['security_baseline', 'compliance']
    data['certname'] = facts.name
    arr = facts.name.split('.')
    data['hostname'] = if arr.empty? || arr.nil?
                         request.node
                       else
                         arr[0]
                       end
    data.merge!(facts.values['security_baseline_summary'])
    data.delete('_@timestamp')
    server = security_baseline_fact_server
    port = security_baseline_fact_server_port
    timeout = security_baseline_fact_timeout

    Puppet.info "sending security_baseline facts to Logstash at #{server}:#{port} for #{request.key}"

    Timeout.timeout(timeout) do
      json = data.to_json
      ls = TCPSocket.new server, port
      ls.puts json
      ls.close
    end

    Puppet.info "finished sending security_baseline facts to Logstash at #{server}:#{port} for #{request.key}"
  end
end
