# security_baseline

#### Table of Contents

1. [Description](#description)
2. [Setup - The basics of getting started with security_baseline](#setup)
    * [What security_baseline affects](#what-security_baseline-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with security_baseline](#beginning-with-security_baseline)
3. [Extend the security baseline](#extend-the-security-baseline)
4. [Usage](#usage)
5. [Reference](#reference)
6. [Limitations](#limitations)
7. [Development](#development)
8. [Changelog](#changelog)
9. [Contributors](#contributors)

## Description

Define a complete security baseline and monitor the baseline's rules. The definition of the baseline can be done in Hiera. The purpose of the module is to give the ability to setup complete security baseline which not necessarily have to stick to industry security guides like the CIS benchmarks.

One main purpose is to ensure the module can be extended by further security settings and monitorings without changing the code of this module. Therefore the module uses a generic interface to call classes implementing particular security baseline rules.

## Setup

It is highly recommended to have the complete security baseline definition written in Hira definitions. This enables you to have different security baselines for groups of servers, environmants or special single servers.

### What security_baseline affects

The security_baseline module has a parameter `enforce`. If this parameter is set to true all necessary changes are made to make a machine compliant to the security baseline. This can have severre impacts to the machines, especially if security settings are defined in a wrong way.

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

Please keep in mind that the classes you want to use for your security basdeline have to available in the Puppet catalog. Otherwise the catalog compliation will fail.

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

### Extension class

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

CVurrently the module is tested with redHat 7 only. If you need your own rules please create Puppet modules and call them from the security baseline module. See [extend the security baseline](#extend-the-security-baseline).

## Development

Contributions are welcome in any form, pull requests, and issues should be filed via GitHub.

## Changelog

See [CHANGELOG.md](https://github.com/tom-krieger/security_baseline/blob/master/CHANGELOG.md)

## Contributors
