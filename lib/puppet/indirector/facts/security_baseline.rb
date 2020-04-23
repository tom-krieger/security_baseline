require 'puppet/indirector/facts/yaml'
require 'puppet/util/profiler'
require 'puppet/util/securityBaseline'
require 'json'
require 'time'

# Logstash Facts
class Puppet::Node::Facts::SecurityBaseline < Puppet::Node::Facts::Yaml
  desc 'Save facts to logstash and then to yamlcache.'

  include Puppet::Util::SecurityBaseline

  def profile(message, metric_id, &block)
    message = 'Security_baseline: ' + message
    # Puppet.info "Message: #{message}"
    arity = Puppet::Util::Profiler.method(:profile).arity
    case arity
    when 1
      Puppet::Util::Profiler.profile(message, &block)
    when 2, -2
      Puppet::Util::Profiler.profile(message, metric_id, &block)
    end
  end

  def save(request)
    # yaml cache goes first
    super(request)

    Puppet.info "Security_baseline indirector save #{request.key}"

    profile('security_baseline_facts#save', [:security_baseline, :facts, :save, request.key]) do
      begin
        # Puppet.info "Submitting facts to Logstash #{request.to_json} |"
        # current_time = Time.now
        send_facts(request, Time.now.strftime('%b %-d, %Y @ %H:%M:%S.%L'))
      rescue StandardError => e
        Puppet.err "Could not send security_baseline facts to Logstash: #{e}\n#{e.backtrace}"
      end
    end
  end
end
