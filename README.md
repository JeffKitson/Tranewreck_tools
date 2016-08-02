# Tranewreck

Tranewreck is a collection of ruby scripts meant to connect with and exploit vulnerable thermostats running ComfortLink II based firmware, specifically the [Trane ComfortLink II XL850](https://www.trane.com/residential/en/products/thermostats-and-controls/connected-controls/comfortlink_xl850.html).  Use these tools only on devices you own or have consent to test. 

There are three tools included in this repository:

  - tranewreck.rb
  - derailer.rb
  - tranewreck_single.rb

## Requirements
These tools are witten in Ruby and you should have a recent version od Ruby installed. If you do not you must [install ruby on your system](https://www.ruby-lang.org/en/documentation/installation/). The package comes with a gem file. To ensure you have everything you need in addition to ruby run: 
```sh
$ cd Tranewreck/
$ bundle install
```

### tranewreck.rb
tranewreck.rb is intended to obtain available information from vulnerable thermostats. It uses default credentials and exploits the plain-text protocol controlling the device. After authenticating with the device commands are issued to obtain the following information:

* installer
  * name
  * address
  * city
  * state
  * zipcode
  * phone
  * website
  * phone_aux
* device
  * system_name
  * auid
  * manufacturer
  * model
  * serial_number
  * version_id
  * platform
* trusted_connections
    * id
    * name
    * host
    * port
    * secure_callout_enabled
    * encrypted_AUID_supported
* schedules
  * name
  * group
  * weekday
  * start
  
  
**Usage:**
```sh
Usage: tranewreck.rb -t [TARGET] [options]

options
    -h, --help                       help
    -t, --target IP                  where?
    -s, --stay                       fire subscribe and stay connected
```

### derailer.rb
Derailer is meant to change heating and cooling points as well as establish and delete trusted server connections. Here be dragons. Using this script my permanently update the settings of the targeted thermostat.

**Useage:**
```sh
Usage: derailer.rb -t [TARGET] [OPTIONS]
Options
    -h, --help                       help
    -t, --target=n                   where?
    -H, --set_heat=n                 set heat int
    -C, --set_cold=n                 set cold int
    -d, --derail=n                   makes new trusted connection to host:port
    -r, --rerail=n                   remove a given server from trusted connections.
```
These tools are a work in progress. 
