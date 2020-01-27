Puppet::Functions.create_function(:'security_baseline::init') do
  dispatch :init do
    optional_param 'String', :filename
    optional_param 'Boolean', :debug
  end

  def init(filename = '/tmp/security_baseline_summary.txt', debug = false)
    return unless File.exist?(filename)

    call_function('info', "init cleanup #{filename}") if debug
    File.delete(filename)
  end
end
