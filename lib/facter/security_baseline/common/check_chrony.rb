def check_chrony(conf, job)
  data = {}
  if !conf.empty? && File.exist?(conf)
    val = Facter::Core::Execution.exec("grep -h -E \"^(server|pool)\" #{conf}")
    data['chrony_server'] = check_value_string(val, 'none')
  else
    data['chrony_server'] = 'none'
  end
  if !job.empty? && File.exist?(job)
    val = Facter::Core::Execution.exec("grep -h -E ^OPTIONS #{job}")
    data['chrony_options'] = check_value_string(val, 'none')
  end

  data
end
