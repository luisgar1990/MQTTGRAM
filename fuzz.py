#!/usr/bin/env python3
#==========================================================================
#    MQTTGRAM: An open source grammar-based fuzzer for the MQTT protocol.
#    Copyright (C) 2020 Luis Gustavo Araujo Rodriguez
#
#    This file is part of MQTTGRAM.
#
#    MQTTGRAM is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    MQTTGRAM is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with MQTTGRAM. If not, see <https://www.gnu.org/licenses/>.
#==========================================================================
from random import choice, choices
from response_engine import tcp_handshake, tcp_disconnect, mqtt_connect, mqtt_disconnect, mqtt_publish, mqtt_subscribe, mqtt_unsubscribe, mqtt_ping, mqtt_random

mqtt_pkts = [
        mqtt_publish, 
        mqtt_subscribe, 
        mqtt_unsubscribe, 
        mqtt_ping, 
        mqtt_disconnect, 
        mqtt_random
        ]

mqtt_pkts_frequency=[
        25, # frequency rate for mqtt_publish
        25, # frequency rate for mqtt_subscribe
        25, # frequency rate for mqtt_unsubscribe
        15, # frequency rate for mqtt_ping
        5,  # frequency rate for mqtt_disconnect
        5   # frequency rate for mqtt_random
        ]


def main():
    
    #TCP HANDSHAKE
    ip_pkt, tcp_pkt, last_pkt = tcp_handshake()

    #MQTT CONNECT
    ip_pkt, tcp_pkt, last_pkt = mqtt_connect(ip_pkt, tcp_pkt, last_pkt)

    while True:
        #NO WEIGHTS
        #random_mqtt_pkt = choice(mqtt_pkts)

        #WEIGHTS
        random_mqtt_pkt = choices(mqtt_pkts, weights=mqtt_pkts_frequency)
        ip_pkt, tcp_pkt, last_pkt = random_mqtt_pkt[0](ip_pkt, tcp_pkt, last_pkt) #OLD
            
        if (last_pkt["TCP"].flags == "FA") or (last_pkt["TCP"].flags == "FPA") or (last_pkt["TCP"].flags == "R"):

            #TCP DISCONNECT
            tcp_disconnect(ip_pkt, tcp_pkt, last_pkt) #OLD

            #TCP HANDSHAKE
            ip_pkt, tcp_pkt, last_pkt = tcp_handshake() #OLD

            #MQTT CONNECT
            ip_pkt, tcp_pkt, last_pkt = mqtt_connect(ip_pkt, tcp_pkt, last_pkt) #OLD

if __name__ == '__main__':
    main()
