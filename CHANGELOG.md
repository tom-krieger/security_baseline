# Changelog

## Release 0.9.2

- changed value names in summary report
- introduced dry run mode which overwrites the enforcing settings of each rule. If dry run ist set to true no rule will be enforced.
- use resource defaults for packages and services
- added facts indirector to send summary facts to logstash
- added some Litmus acceptance testing
- fixed a bug in package handling in Debian like OS

## Release 0.9.1

- Added summary report fact
- Bug fix: fixed sed commands for Redhat/CentOS 8
- fixed some check rules
- moved fact for cron restrictions into a function to remove duplicated code

## Release 0.9.0

Initial release including Redhat 6, 7, 8, CentOS 6, 7, 8, Suse SLES 12, Debian 9 and Ubuntu 18.04.
