# MQTTGRAM: An open source grammar-based fuzzer for the MQTT protocol

## Context
The Message Queueing Telemetry Transport (MQTT) is a publish-subscribe messaging
protocol developed by IBM in 1999. MQTT has two main components: MQTT clients
and MQTT brokers. An MQTT client can be either a publisher or subscriber. A
publisher sends messages to subscribers, however messages are not sent directly.
The MQTT broker receives messages from publishers and sends them to interested
subscribers.

## Objective
This repository contains the source code of MQTTGRAM, which is a grammar-based
fuzzer for MQTT implementations.

## Usage

Run the following command to execute MQTTGRAM. By default, MQTTGRAM sends
random packets to the IP address 192.168.33.20.

```bash
python3 fuzz.py
```
The command may need to be executed with `sudo` in the case of _permission errors_ . 

## Requirements

The following software has to be installed for MQTTGRAM to work properly:
* [Python 3](https://www.python.org/)
* [Scapy](https://scapy.net/) 

MQTTGRAM was developed, tested, and used on Ubuntu Mate 20.04 LTS, which has
installed the following software:

* Python 3.8.10
* Scapy 2.4.4

## Limitations

The MQTT Grammar is based only on version 3.1.1 of the standard.

## License

MQTTGRAM is available under *GPL-2.0-or-later*, meaning developers can use,
modify and redistribute the source code according to their needs.
