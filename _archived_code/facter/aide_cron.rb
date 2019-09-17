# frozen_string_literal: true

# aide_cron.rb
# Ensures that aide cronjob is setup
Facter.add('aide_cron') do
  confine kernel: 'Linux'
  setcode do
    cronentry = Facter::Core::Execution.exec('crontab -u root -l | grep aide')
    fileentry = Facter::Core::Execution.exec('grep -rh aide /etc/cron.* /etc/crontab')

    if cronentry.empty? && fileentry.empty?
      ret = 'undef'
    else
      unless cronentry.empty?
        ret = cronentry
      end
      unless fileentry.empty?
        ret = fileentry
      end
    end

    ret
  end
end
