# frozen_string_literal: true

# get facts about aide

def read_facts_aide(os)
  aide = {}
  cronentry = Facter::Core::Execution.exec('crontab -u root -l | grep aide')
  fileentry = Facter::Core::Execution.exec('grep -rh aide /etc/cron.* /etc/crontab')

  if (cronentry.nil? || cronentry.empty?) && (fileentry.nil? || fileentry.empty?)
    aide['cron'] = 'none'
  else
    unless cronentry.empty?
      aide['cron'] = cronentry
    end
    unless fileentry.empty?
      aide['cron'] = fileentry
    end
  end

  case os
  when 'redhat'
    val = Facter::Core::Execution.exec("rpm -q --queryformat '%{version}' aide")
    if val.empty? || val =~ %r{not installed}
      aide['version'] = 'none'
      aide['status'] = 'not installed'
    else
      aide['version'] = check_value_string(val, 'none')
      aide['status'] = 'installed'
    end
  when 'debian'
    val = Facter::Core::Execution.exec('dpkg -s aide')
    if val.empty? || val =~ %r{not installed}
      aide['version'] = 'none'
      aide['status'] = 'not installed'
    else
      aide['version'] = check_value_string(val, 'none')
      aide['status'] = 'installed'
    end
  when 'suse'
    val = Facter::Core::Execution.exec('rpm -q aide')
    if val.empty? || val =~ %r{not installed}
      aide['version'] = 'none'
      aide['status'] = 'not installed'
    else
      aide['version'] = check_value_string(val, 'none')
      aide['status'] = 'installed'
    end
  end

  aide
end
