# security_baseline

#### Table of Contents

1. [Description](#description)
2. [CIS Benchmark Reference](#CIS-Benchmark-Reference)
2. [Setup - The basics of getting started with security_baseline](#setup)
    * [What security_baseline affects](#what-security_baseline-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with security_baseline](#beginning-with-security_baseline)
    * [Passing additional data to rules](#passing-additional-data-to-rules)
    * [Reporting](#reporting)
3. [Checking facts](#checking-facts)
3. [Extend the security baseline](#extend-the-security-baseline)
4. [Usage](#usage)
5. [Reference](#reference)
6. [Limitations](#limitations)
7. [Development](#development)
8. [Changelog](#changelog)
9. [Contributors](#contributors)

## Description

Define a complete security baseline and monitor the baseline's rules. The definition of the baseline should be done in Hiera. The purpose of the module is to give the ability to setup a complete security baseline which not necessarily have to stick to industry security guides like the CIS benchmarks.

This project is highly inspired by the [fervid/secure_linux_cis](https://forge.puppet.com/fervid/secure_linux_cis) module from Puppet Forge. 

This module does not use bechmark numbers for the class names of the rules as these numbers change from OS version to OS version. One main purpose is to ensure the module can be extended by further security settings and monitorings without changing the code of this module. Therefore the module uses a generic interface to call classes implementing particular security baseline rules.

This module also has the ability to create compliance reports. The reports can be created as a Puppet fact uploaded to the Puppet Master or as a CSV file which will remain on the servers for later collection.

## CIS Benchmark Reference

The code of this security baseline module is based on the following CIS Benchmarks:

| OS           | Benchmark version                                            |
|--------------|--------------------------------------------------------------|
| Suse SLES 12 | CIS SUSE Linux Enterprise 12 Benchmark v2.1.0 - 12-28-2017   |
| RedHat 6     | CIS Red Hat Enterprise Linux 6 Benchmark v2.1.0 - 12-27-2017 |
| RedHat 7     | CIS Red Hat Enterprise Linux 7 Benchmark v2.2.0 - 12-27-2017 |
| RedHat 8     | CIS Red Hat Enterprise Linux 8 Benchmark v1.0.0 - 09-30-2019 |
| CentOS 6     | CIS CentOS Linux 6 Benchmark v2.1.0 - 12-27-2017             |
| CentOS 7     | CIS CentOS Linux 7 Benchmark v2.2.0 - 12-27-2017             |
| CentOS 8     | CIS CentOS Linux 8 Benchmark v1.0.0 - 10-31-2019             |
| Ubuntu 18.04 | CIS Ubuntu Linux 18.04 LTS Benchmark v1.0.0 - 08-13-2018     |

## Setup

It is highly recommended to have the complete security baseline definition written in Hira definitions. This enables you to have different security baselines for groups of servers, environmants or special single servers.

### What security_baseline affects

The security_baseline module has a parameter `enforce`. If this parameter is set to true all necessary changes are made to make a machine compliant to the security baseline. This can have severre impacts to the machines, especially if security settings are defined in a wrong way.

The module needs a base directory. This directory is created by the module during the fist run and is `/usr/share/security_baseline`. Some data is collected with cron jobs once a day as collecting these data is depending on the server size somewhat expensive and time consuming, e. g. searching als s-bit programs .

### Setup Requirements

The security_baseline module needs some other puppet modules. These modules are defined in the [metadata.json](https://github.com/tom-krieger/security_baseline/blob/master/metadata.json) file.

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

The 'data' folder contains example Hiera definitions for various OSes.

### Passing additional data to rules

Sometimes rules need additional data, especially if the security benchmark requirements should be enforced. The following example shows the Hirea configuration.

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

All data below the `config_data` entry is passed as parameters to the class for the rule together with the common parameters for `enforce´, `log_level` and ´message`. The class must be capable of accept and use these additional these parameters.

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

### Reporting

This module knows two possible methods of reporting. First you can create a Puppet fact with the reporting results and upload this fact to the Puppet Master. Or you choose to create a csv report which will be stored on the server and can be collected afterwards with some collecting job.

Reporting is configured as follows

```puppet
class { 'security_baseline':
  reporting_type => 'fact',
  logfile => '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml',
}
```

or for csv file creation

```puppet
class { 'security_baseline':
  reporting_type => 'csv_file',
  logfile => '/usr/share/security_baseline/logs/security_baseline_findings.csv',
}
```

## Checking facts

For reporting purposes it is necessary that the security settuings required by a benchmark are checked.

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

This parameter cn be eiterh a string or an array. In case of a strig the string is the name of the fact within the `security_baseline` hash. In case of an array, the array witll be expanded into an array access to the hsh. For the example for the cramfs kernel module above the fact will be looked up like `$facts['security_baseline']['kernel_modules']['cramfs']`.

### fact_value

The value the fact is compared against. In case of a single value the value of the fact is compared to the value given. In case of an array, all values of the array have to be in the fact and the fact should nt contain any additional values.

## Extend the security baseline

To extend the security baseline module you can write your own Puppet modules. These modules must implement a particular interface. This interface has to consume the following parameters.

```puppet
class your_class_name (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = '',
  Optional[Hash] $config_data = {}
) {
     ...
}
```

Please keep in mind that the classes you want to use for your security baseline have to be available in the Puppet catalog. Otherwise the catalog compliation will fail.

### Parameter `enforce`
 
This parameter controls if the security settings should be monitored only or if the system should be changed. Setting enforce to `true` will normaly change your system to be compliant to the security settings. A value of `false` just prints messages if the system is not compliant to the rules.

### Parameter `message`

The message to log if the system is not compliant and enforce is set to false.

### Parameter `loglevel`

The log level the message should be logged.

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
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = '',
  Optional[Hash] $config_data = {}
) {
  if($config_data) {
    validate_hash($config_data)
  }
  ...
}
```

### Extension class Hiera data

```puppet
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

Currently the module is tested with RedHat 6, 7, 8, CentOS 6, 7, 8, Suse SLES 12 and Ubuntu 18.04 (partially tested). Other OSes may work but there's no guarantee. If you need your own rules please create Puppet modules and call them from the security baseline module. See [extend the security baseline](#extend-the-security-baseline).

## Development

Contributions are welcome in any form, pull requests, and issues should be filed via GitHub.

## Changelog

See [CHANGELOG.md](https://github.com/tom-krieger/security_baseline/blob/master/CHANGELOG.md)

## Contributors
