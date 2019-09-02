# frozen_string_literal: true

# aide_cron.rb
# Ensures that aide cronjob is setup
Facter.add('aide_cron') do
  confine :kernel => 'Linux'
  setcode do
    ret = 'undef'
    cronentry = Facter::Core::Execution.exec("crontab -u root -l | grep aide")
    fileentry = Facter::Core::Execution.exec("grep -rh aide /etc/cron.* /etc/crontab")
    if cronentry.empty? and fileentry.empty? then
      ret = 'undef'
    else
      if ! cronentry.empty? then
        ret = cronentry
      end
      if ! fileentry.empty? then
        ret = fileentry
      end
    end

    ret
  end
end
  