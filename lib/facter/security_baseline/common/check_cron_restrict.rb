def check_cron_restrict(cron)
  if (cron['/etc/cron.allow']['uid'] != 0) ||
     (cron['/etc/cron.allow']['gid'] != 0) ||
     (cron['/etc/cron.allow']['mode'] != 384) ||
     (cron['/etc/at.allow']['uid'] != 0) ||
     (cron['/etc/at.allow']['gid'] != 0) ||
     (cron['/etc/at.allow']['mode'] != 384)
    false
  elsif cron['/etc/cron.deny']['uid'] != 'none' ||
        cron['/etc/at.deny']['uid'] != 'none'
    false
  else
    true
  end
end
