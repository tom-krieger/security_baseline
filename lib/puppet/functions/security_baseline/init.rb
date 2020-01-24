Puppet::Functions.create_function(:'security_baseline::init') do
  dispatch :init do
  end

  def init
    File.delete('/tmp/security_baseline_summary.txt') if File.exist?('/tmp/security_baseline_summary.txt')
    File.open('/tmp/security_baseline_summary.txt', 'w') { |file|
      file.write("ok:\n")
      file.write("fail:\n")
      file.write("unknown:\n")
    }
  end
end
