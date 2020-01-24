Puppet::Functions.create_function(:'security_baseline::cleanup') do
  dispatch :cleanup do
    optional_param 'String', :filename
  end

  def cleanup(filename = '/tmp/security_baseline_summary.txt')
    File.delete(filename) if File.exist?(filename)

    nil
  end
end
