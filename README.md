# security_baseline

#### Table of Contents

1. [Description](#description)
2. [Security baseline](#security-baseline)
2. [CIS Benchmark Reference](#CIS-Benchmark-Reference)
2. [Setup - The basics of getting started with security_baseline](#setup)
    * [What security_baseline affects](#what-security_baseline-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with security_baseline](#beginning-with-security_baseline)
    * [Passing additional data to rules](#passing-additional-data-to-rules)
    * [Cronjobs](#cronjobs)
    * [Reporting](#reporting)
    * [Example Hiera files](#example-hiera-files)
3. [Checking facts](#checking-facts)
3. [Extend the security baseline](#extend-the-security-baseline)
4. [Usage](#usage)
5. [Reference](#reference)
6. [Limitations](#limitations)
    * [Auditd](#auditd)
    * [SELinux and Apparmor](#selinux-and-apparmor)
    * [Automatic reboot](#automatic-reboot)
7. [Credits](#credits)
7. [Development](#development)
8. [Changelog](#changelog)
9. [Contributors](#contributors)
10. [Warranty](#warranty)

## Description

Define a complete security baseline and monitor the baseline's rules. The definition of the baseline should be done in Hiera. The purpose of the module is to give the ability to setup a complete security baseline which not necessarily have to stick to industry security guides like the CIS benchmarks.

The `security_baseline` module does not use bechmark numbers for the class names of the rules. These numbers change from OS version to OS version and even from benchmark version to benchmark version. One main purpose is to ensure this module can be extended by further security settings and monitorings without changing the code of this module. Therefore the module uses a generic interface to call classes implementing particular security baseline rules.

This module also has the ability to create compliance reports. The reports can be created as a Puppet fact uploaded to the Puppet Master or as a CSV file which will remain on the servers for later collection.

## Security baseline

A security baseline describes how servers in your environment are setup with a secure configuration. The baseline may be different each server class like database servers, application or web servers. 

A security baseline can be based on a CIS benchmark but can include more rules specific to your environment. But depending on server classes not all rules of a CIS benchmark will be used. Sometimes the benchmarks contain different ways to achieve a goal, e.g. with RedHat 8 you can use firewalld, iptables or nftables to setup a firewall. Surely it makes no sense to have all of them running in parallel. So it is your task to define a security baseline to define which tool to use or which settings to use. 

> For this module level 1 and level 2 server tests from the CIS benchmarks below are taken into account.

## CIS Benchmark Reference

The code of this security baseline module is based on the following CIS Benchmarks:

| OS           | Benchmark version                                            | Version | Date       |
|--------------|--------------------------------------------------------------|---------|------------|
| Suse SLES 12 | CIS SUSE Linux Enterprise 12 Benchmark                       | 2.1.0   | 12-28-2017 |
| RedHat 6     | CIS Red Hat Enterprise Linux 6 Benchmark                     | 2.1.0   | 12-27-2017 |
| RedHat 7     | CIS Red Hat Enterprise Linux 7 Benchmark                     | 2.2.0   | 12-27-2017 |
| RedHat 8     | CIS Red Hat Enterprise Linux 8 Benchmark                     | 1.0.0   | 09-30-2019 |
| CentOS 6     | CIS CentOS Linux 6 Benchmark                                 | 2.1.0   | 12-27-2017 |
| CentOS 7     | CIS CentOS Linux 7 Benchmark                                 | 2.2.0   | 12-27-2017 |
| CentOS 8     | CIS CentOS Linux 8 Benchmark                                 | 1.0.0   | 10-31-2019 |
| Ubuntu 18.04 | CIS Ubuntu Linux 18.04 LTS Benchmark                         | 2.0.1   | 01-03-2020 |
| Debian 9     | CIS Debian Linux 9 Benchmark                                 | 1.0.1   | 01-13-2020 |

The benchmarks can be found at [CIS Benchmarks Website](https://www.cisecurity.org/cis-benchmarks/).

## Setup

It is highly recommended to have the complete security baseline definition written in Hira definitions. This enables you to have different security baselines for groups of servers, environments or even special single servers.

### What security_baseline affects

The *security_baseline* module has a parameter `enforce` for each rule. If this parameter is set to true all necessary changes are made to make a server compliant to the security baseline rules. This can have severe impacts to the machines, especially if security settings are defined in a wrong way. 
> Please test your settings before rolling out to production environments.

The module needs a base directory. The base directory `/usr/share/security_baseline` is created by the module during the fist run. Some data is collected with cron jobs once a day as collecting this data is somewhat expensive and time consuming depending on the server size, e. g. searching als s-bit programs . Under the base directory there will be a directory `bin` where all scripts for gathering information are located.

This module creates a larger fact `security_baseline` to have all needed information for applying the rules. Some information is collected with cron jobs once a day as these jobs might run for a long time (e. g. searching filesystems for s-bit programs).

### Setup Requirements

The *security_baseline* module needs some other Puppet modules. These modules are defined in the [metadata.json](https://github.com/tom-krieger/security_baseline/blob/master/metadata.json) file and are all available at [Puppet Forge](https://forge.puppet.com/).

### Beginning with security_baseline

The most easiest way to use the security baseline module is just calling the class or including the class.

```puppet
class { 'security_baseline':
}
```

or

```puppet
include ::security_baseline
```

The `data` folder contains example Hiera definitions for various operation systems.

### Passing additional data to rules

Sometimes rules need additional data, especially if the security benchmark requirements should be enforced. The following example shows the Hirea configuration how to pass these parameters to the class implementing the rule.

```hiera
---
'2.2.1.2':
    rulename: 'ntp'
    active: true
    scored: true
    level: 1
    description: 'ntp is a daemon which implements the Network Time Protocol (NTP). It is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on NTP can be found at http://www.ntp.org. ntp can be configured to be a client and/or a server. This recommendation only applies if ntp is in use on the system.'
    enforce: true
    class: '::security_baseline::rules::redhat::sec_ntp_daemon_ntp'
    check:
      fact_hash: security_baseline
      fact_name:
        - ntp
        - ntp_status
      fact_value: true
    message: 'Rule 2.2.1.2. NTP should be configured propperly.'
    log_level: 'warning'
    config_data:
      ntp_servers: 
        - 0.de.pool.ntp.org
        - 1.de.pool.ntp.org
        - 2.de.pool.ntp.org
      ntp_restrict:
        - 127.0.0.1
        - default kod nomodify notrap nopeer
        - '-6 default kod nomodify notrap nopeer'
      ntp_driftfile: '/var/lib/ntp/ntp.drift'
      ntp_statsdir: '/var/log/ntpstats/'
      ntp_disable_monitor: true
      ntp_burst: true
```

All data below the `config_data` entry is passed as parameters to the class for the rule together with the common parameters for `enforce`, `log_level` and `message`. The class must be capable of accept and use these additional parameters.

The class `security_baseline::rules::redhat::sec_ntp_daemon_ntp` from the Hiera example above is defined as follows

```puppet
class security_baseline::rules::redhat::sec_ntp_daemon_ntp (
  Boolean $enforce                        = true,
  String $message                         = '',
  String $log_level                       = '',
  Array $ntp_servers                      = [],
  Array $ntp_restrict                     = [],
  String $ntp_driftfile                   = '',
  String $ntp_statsdir                    = '',
  Boolean $ntp_disable_monitor            = true,
  Boolean $ntp_burst                      = false,
) {
}
```

### Cronjobs

Gathering information can sometime consume a lot of time. Gathering those facts during Puppet runs would have a significat impact on the time consumed by a Puppet run. Therefore some facts are only gathered once a day using cron jobs. The `security_baseline` module installes the following cron jobs to collect information and provide the information to the fact scripts creating the `security_baseline` fact.

#### Cron /etc/cron.d/system-file-permissions.cron

This cron job runs a verrify for rpm or dpkg packages and checks for changes file permissions and so on.

#### Cron /etc/cron.d/unowned-files.cron

This cron job searches for unowned and ungrouped files.

#### Cron /etc/cron.d/world-writebale-files.cron

This cron job searches for world writable files.

#### Cron /etc/cron.daily/suid-audit

Search for s-uid programs to create auditd rules for those binaries.

### Reporting

This module has two possible methods of reporting. First you can create a Puppet fact with the reporting results and upload this fact to the Puppet Master. Or you choose to create a CSV report which will be stored on the server and can be collected afterwards with some collecting job.

Reporting is configured as follows

```puppet
class { 'security_baseline':
  reporting_type => 'fact',
  logfile => '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml',
}
```

or for CSV file creation

```puppet
class { 'security_baseline':
  reporting_type => 'csv_file',
  logfile => '/usr/share/security_baseline/logs/security_baseline_findings.csv',
}
```

### Example Hiera files

The `data` directory contains example Hiera data for various operating systems. Please do not use these files without reviewing them *carefully*. The configuration in these files may or may not fit your needs or can even crash your systems. 
> *You are strongly advised to review the files before using them and adapt them to your needs.*

## Checking facts

For reporting purposes it is necessary that the security settings required by a baseline are checked.

```hiera
---
'1.1.1.1':
    rulename: 'cramfs'
    active: true
    scored: true
    level: 1
    description: 'The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A cramfs image can be used without having to first decompress the image.'
    enforce: true
    class: '::security_baseline::rules::common::sec_cramfs'
    check:
      fact_hash: security_baseline
      fact_name: 
        - kernel_modules
        - cramfs
      fact_value: false
    message: 'Rule 1.1.1.1. Cramfs kernel module should not be available.'
    log_level: 'warning'
'5.2.11':
    rulename: sshd-macs
    active: true
    scored: true
    level: 1
    description: 'This variable limits the types of MAC algorithms that SSH can use during communication.'
    enforce: true
    class: '::security_baseline::rules::common::sec_sshd_macs'
    check:
      fact_hash: security_baseline
      fact_name:
        - sshd
        - macs
      fact_value: 
        - hmac-sha2-512
        - hmac-sha2-256
    message: 'Rule 5.2.11. The sshd parameter MACs should be configured with strong MAC algorithms.'
    log_level: warning
    config_data:
      macs:
        - hmac-sha2-512
        - hmac-sha2-256
```

The example above contains two rule definitions from a Hirea file. The first example shows how to check for a simple fact value. The second example shows how to provide multiple values to be checked.

For the first example the fact `$facts['security_baseline']['kernel_modules']['cramfs']` has to be `false`. For the second example the fact `$facts['security_baseline']['sshd']['macs']` has to contain only the values hmac-sha2-5 and hmac-sha2-256.

Parameters of the `check` hash:

### fact_hash

The fact hash tells the module wich fact hash contains the facts to check. This is normally `security_baseline`.

### fact_name

This parameter can be either a string or an array. In case of a string the string is the name of the fact within the `security_baseline` hash. In case of an array, the array will be expanded into an array access to the hash. For the example for the cramfs kernel module above the fact will be looked up like `$facts['security_baseline']['kernel_modules']['cramfs']`.

### fact_value

The value the fact is compared against. In case of a single value the value of the fact is compared to the value given. In case of an array, all values of the array have to be in the fact and the fact should not contain any additional values.

## Extend the security baseline

To extend the security baseline module you can write your own Puppet modules. These modules must implement a particular interface. This interface has to consume the following parameters.

```puppet
class your_class_name (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '', 
  String $logfile             = '',
  Optional[Hash] $config_data = {}
) {
     ...
}
```

> Please keep in mind that the classes you want to use for your security baseline have to be available in the Puppet catalog. Otherwise the catalog compliation will fail.

### Parameter `enforce`
 
This parameter controls if the security settings should be monitored only or if the system should be changed. Setting enforce to `true` will normaly change your system to be compliant to the security settings. A value of `false` just prints messages if the system is not compliant to the rules.

### Parameter `message`

The message to log if the system is not compliant and enforce is set to false.

### Parameter `log_level`

The log level the message should be logged.

### Parameter `logfile`

The `logfile` parameter gives you the ability to write to the logfile. You can use the `logging` resource defined in this module to do this.

### Parameter `config_data`

This parameter has to be a hash. The structure of the hash can be freely defined. The module consuming that hash has to be aware of the structure of that hash.

## Usage

The most easiest way to use the security baseline module is just calling the class or including the class. The security baseline data has to be defined in a Hiera configuration file.

```puppet
class { 'security_baseline':

}
```

or

```puppet
include ::security_baseline
```

Hiera data:

```hiera
---
security_baseline::baseline_version: '1.0.0'
security_baseline::debug: false
security_baseline::log_info: true
security_baseline::auditd_suid_include:
  - /usr
security_baseline::update_postrun_command: true
security_baseline::reporting_type: fact
security_baseline::logfile: /opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml
security_baseline::auditd_rules_file: /etc/audit/rules.d/sec_baseline_auditd.rules
security_baseline::auditd_rules_fact_file: /opt/puppetlabs/facter/facts.d/security_baseline_auditd.yaml
security_baseline::reboot: false
security_baseline::reboot_timeout: 120
security_baseline::rules:
  '1.1.1.1':
    rulename: 'cramfs'
    active: true
    description: 'Support for cramfs removed'
    enforce: true
    class: 'sec_cramfs'
    check:
      fact_name: 'kmod_cramfs'
      fact_value: false
  '1.1.1.2':
    rulename: 'freevxfs'
    active: true
    description: 'Support for freevxfs removed'
    enforce: true
    class: 'sec_freevxfs'
    check:
      fact_name: 'kmod_freevxfs'
      fact_value: false

```

### Extension classes

The security baseline module contains a lot of classes to make your system complinat to a security guide. But some companies have own security baselines with own rules. Therefore the security baseline module can be extended by custom modules. You can add your own classes if these classes implement the interface described [above](#extend-the-security-baseline)

```puppet
class your_class_name (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
  String $logfile             = '',
  Optional[Hash] $config_data = {}
) {
  if($config_data) {
    validate_hash($config_data)
  }
  ...
}
```

### Extension class Hiera data

```hiera
---
'2.2.1.2':
  rulename: 'ntp'
  active: true
  description: 'ntp is a daemon which implements the Network Time Protocol (NTP).'
  enforce: true
  class: '::security_baseline_ntp'
  check:
    fact_name: ''
    fact_value: ''
  message: 'Not in compliance with rule 2.2.1.2. NTP not configured.'
  loglevel: 'warning'
  config_data:
    ntp_daemon: 'ntp'
    ntp_servers: 
      - 0.de.pool.ntp.org
      - 1.de.pool.ntp.org
      - 2.de.pool.ntp.org
```

## Reference

See [REFERENCE.md](https://github.com/tom-krieger/security_baseline/blob/master/REFERENCE.md)

## Limitations

Currently the module is tested with RedHat 6, 7, 8, CentOS 6, 7, 8, Suse SLES 12, Debian 9 (partly tested) and Ubuntu 18.04 (partially tested). Other OSes may work but there's no guarantee. If you need your own rules please create Puppet modules and call them from the security baseline module. See [extend the security baseline](#extend-the-security-baseline).

More testing is needed as for every supported OS there are different setups in the wild and some of them might not be covered. 

### Auditd

Auditd is normally configured with immutal rules. This meens that changing rules will require a *reboot* to make the new rules effective.

### SELinux and Apparmor

SELinux and AppArmor are - if configured - activated while this module is applied. To make them effective a *reboot* is required.

### Automatic reboot

Automatic reboots might be *dangerous* as servers would be rebooted if one of the classes subscribed for reboot takes any action. But some changes need a reboot, e. g. enabling SELinux or changing auditd rules. As servers in production environments may not be rebooted you have to choose if you will allow reboots by settings a global parameter *security_baseline::reboot* and you can add a parameter reboot to each rule.

The global *reboot* parameter enables or disables reboots regardless of the settings rules have. The *reboot* parameter given with a rule will subscribe the class implementing the rule to the reboot module. If the rule takes any action a reboot will be triggered.

The reboot timeout will shedule a reboot within the given time after applying the catalogue finished.

```hiera
---
security_baseline::reboot: true
security_baseline::reboot_timeout: 120
security_baseline::rules:
  '1.6.1.1':
    rulename: 'selinux-bootloader'
    active: true
    scored: true
    level: 2
    description: 'Configure SELINUX to be enabled at boot time and verify that it has not been overwritten by the grub boot parameters.'
    enforce: true
    class: 'security_baseline::rules::redhat::sec_selinux_bootloader'
    check:
      fact_hash: security_baseline
      fact_name: 
        - selinux
        - bootloader
      fact_value: true
    message: 'Rule 1.6.1.1. All linux bootloader entries should enforce selinux.'
    log_level: 'warning'
    reboot: true
```

## Credits

This project is highly inspired by the [fervid/secure_linux_cis](https://forge.puppet.com/fervid/secure_linux_cis) module from Puppet Forge. 

## Development

Contributions are welcome in any form, pull requests, and issues should be filed via GitHub.

## Changelog

See [CHANGELOG.md](https://github.com/tom-krieger/security_baseline/blob/master/CHANGELOG.md)

## Contributors

The list of contributors can be found at: [https://github.com/tom-krieger/security_baseline/graphs/contributors](https://github.com/tom-krieger/security_baseline/graphs/contributors).

## Warranty

This Puppet module is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the Apache 2.0 License for more details.
