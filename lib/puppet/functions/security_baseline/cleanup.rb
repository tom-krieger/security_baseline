Puppet::Functions.create_function(:'security_baseline::cleanup') do
  dispatch :cleanup do
  end

  def cleanup
    File.delete('/tmp/security_baseline_summary.txt') if File.exist?('/tmp/security_baseline_summary.txt')
  end
end
