Puppet::Functions.create_function(:'security_baseline::init') do
  dispatch :init do
  end

  def init
    File.delete('/tmp/security_baseline_summary.txt') if File.exist?('/tmp/security_baseline_summary.txt')
  end
end
