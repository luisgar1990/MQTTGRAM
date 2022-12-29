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
from random import randint
from scapy.all import *
from scapy.contrib.mqtt import *
from generator import generate_packet

mqtt_broker_ip = '192.168.33.20'

mqtt_broker_port = 1883
host_port = randint(1024, 60000) #CHOOSE RANDOM PORT

qos_lvls = [0, 1, 2]

def tcp_handshake():

    global host_port #PORT OF HOST MACHINE
    host_port+=2

    i = IP()
    i.dst = mqtt_broker_ip
    i.src = "192.168.33.1"

    t = TCP()
    t.dport = 1883
    t.sport = host_port
    t.flags = "S"

    while(True):
        SYNACK = sr1(i/t, timeout=0.1, retry=3)
        if not SYNACK: 
            t.sport = host_port
            continue
        else:
            break

    t.flags = "A"
    t.seq = SYNACK.ack
    t.ack = SYNACK.seq + 1

    send(i/t)
    return i, t, SYNACK

def tcp_acknowledgment(t, lp):

    if lp.haslayer(MQTT) and lp.haslayer(Padding): 
        t.ack = lp.seq + (len(lp[MQTT]) - len(lp[Padding]))
    elif lp.haslayer(MQTT) and lp.haslayer(Padding) == 0:
        t.ack = lp.seq + len(lp[MQTT])
    else:
        t.ack = lp.seq + 0

    return t

def mqtt_random(i, t, lp):

    pkts = [
            "<CONNACK>", 
            "<SUBACK>", 
            "<UNSUBACK>", 
            "<PINGRESP>", 
            "<PUBCOMP>", 
            "<PUBREC>", 
            "<PUBREL>", 
            "<PUBACK>"
            ] #FOR MQTT 3.1.1

    t.flags = "PA"
    t.seq = lp.ack
    t = tcp_acknowledgment(t, lp)

    while(True):
        try:
            m = generate_packet(choice(pkts))
        except UnicodeDecodeError:
            continue
        break

    ans, unans = sr(i/t/m, multi=1, timeout=0.1, retry=3)

    try:
        answer = ans[-1][-1]
    except IndexError:
        lp[TCP].flags = "FA"
        return i, t, lp

    return i, t, answer

def mqtt_pubcomp(i, t, lp):

    t.flags = "PA"
    t.seq = lp.ack

    if lp.haslayer(MQTTPubrel) and lp.haslayer(Padding): 
        t.ack = lp.seq + (len(lp[MQTT]) - len(lp[Padding]))
    elif lp.haslayer(MQTTPubrel) and lp.haslayer(Padding) == 0:
        t.ack = lp.seq + len(lp[MQTT])
    else:
        return i, t, lp #IF PACKET IS RESET (RST) RETURN TO DISCONNECT


    m = generate_packet("<PUBCOMP>")
    m.msgid = lp.msgid
    pubcomp_pkt = i/t/m

    ans, unans = sr(pubcomp_pkt, multi=1, timeout=0.1, retry=3)

    try:
        PUBCOMP_ACK = ans[-1][-1]
    except IndexError:
        lp[TCP].flags = "FA"
        return i, t, lp

    return i, t, PUBCOMP_ACK

def mqtt_pubrec(i, t, lp):

    t.flags = "PA"
    t.seq = lp.ack

    if lp.haslayer(MQTT) and lp.haslayer(Padding): 
        t.ack = lp.seq + (len(lp[MQTT]) - len(lp[Padding]))
    elif lp.haslayer(MQTT) and lp.haslayer(Padding) == 0:
        t.ack = lp.seq + len(lp[MQTT])

    m = generate_packet("<PUBREC>")
    m.msgid = lp.msgid
    pubrec_pkt = i/t/m

    ans, unans = sr(pubrec_pkt, multi=1, timeout=0.1, retry=3)

    try:
        PUBREL = ans[-1][-1]
    except IndexError:
        lp[TCP].flags = "FA"
        return i, t, lp

    return i, t, PUBREL

def mqtt_puback(i, t, lp):

    t.flags = "PA"
    t.seq = lp.ack

    if lp.haslayer(MQTT) and lp.haslayer(Padding): 
        t.ack = lp.seq + (len(lp[MQTT]) - len(lp[Padding]))
    elif lp.haslayer(MQTT) and lp.haslayer(Padding) == 0:
        t.ack = lp.seq + len(lp[MQTT])

    m = generate_packet("<PUBACK>")
    m.msgid = lp.msgid
    puback_pkt = i/t/m

    ans, unans = sr(puback_pkt, multi=1, timeout=0.1, retry=3)
    
    try:
        PUBACK_ACK = ans[-1][-1]
    except IndexError:
        lp[TCP].flags = "FA"
        return i, t, lp

    return i, t, PUBACK_ACK

def respond_publish(i, t, PUBLISH):

    if PUBLISH.QOS == 0:
        t.flags = "A"
        t.seq = PUBLISH.ack

        if PUBLISH.haslayer(Padding): 
            t.ack = PUBLISH.seq + (len(PUBLISH[MQTT]) - len(PUBLISH[Padding]))
        else:
            t.ack = PUBLISH.seq + len(PUBLISH[MQTT])
       
        ACK = i/t
        PUBLISH_ACK = sr1(ACK, timeout=0.1)

        if PUBLISH_ACK is None:
            return i, t, PUBLISH
        else:
            return i, t, PUBLISH_ACK

    elif PUBLISH.QOS == 1:
            i, t, PUBACK_ACK = mqtt_puback(i, t, PUBLISH) 
            return i, t, PUBACK_ACK
    
    elif PUBLISH.QOS == 2:
            i, t, PUBREL = mqtt_pubrec(i, t, PUBLISH)
            i, t, PUBCOMP_ACK = mqtt_pubcomp(i, t, PUBREL)
            return i, t, PUBCOMP_ACK


def mqtt_connect(i, t, lp):
    
    t.flags = "PA"

    m = generate_packet("<CONNECT>")
    connect_pkt = i/t/m

    ans, unans = sr(connect_pkt, multi=1, timeout=0.1, retry=3)

    try:
        CONACK = ans[-1][-1]
    except IndexError:
        lp[TCP].flags = "FA"
        return i, t, lp
        
    #IF STATEMENT ADDED TO CLOSE CONNECTION IF BROKER SENT A PACKET THAT IS NOT CONNACK
    if CONACK.haslayer(MQTTConnack) == 0: 
        CONACK[TCP].flags = "FA"
        return i, t, CONACK

    t.flags = "A"
    t.seq = CONACK.ack
    t = tcp_acknowledgment(t, CONACK)

    PUBLISH = sr1(i/t, timeout=0.1)

    if not PUBLISH:
        return i, t, CONACK
    else:
        if PUBLISH.haslayer(MQTTPublish):
            i ,t, lp = respond_publish(i, t, PUBLISH)
            return i, t, lp
        if PUBLISH.haslayer(MQTTPubrel):
            i, t, lp = mqtt_pubcomp(i, t, PUBLISH)
            return i, t, lp
            

def mqtt_publish(i, t, lp):

    t.flags = "PA"
    t.seq = lp.ack
    t = tcp_acknowledgment(t, lp)

    while(True):
        try:
            m = generate_packet("<PUBLISH>")
        except UnicodeDecodeError:
            continue
        break

    publish_pkt = i/t/m

    ans, unans = sr(publish_pkt, multi=1, timeout=0.1, retry=3)

    try:
        ACK = ans[-1][-1] # FOR QOS0 ONLY
    except IndexError:
        publish_pkt[TCP].flags = "FA"
        return i, t, publish_pkt

    #CHECK IF PACKET RECEIVED IS A PUBLISH
    if ACK.haslayer(MQTTPublish): 
        i ,t, ACK = respond_publish(i, t, ACK)

    if (publish_pkt.QOS == 0):
        return i, t, ACK
    elif (publish_pkt.QOS == 1): 
        #IF STATEMENT ADDED TO CLOSE CONNECTION IF SERVER DISCONNECTS AFTER SENDING PUBLISH QOS1 PACKET
        if ACK.haslayer(MQTTPuback) == 0: 
            return i, t, ACK

        PUBACK = ACK

        t.flags = "A" 
        t.seq = PUBACK.ack 
        t = tcp_acknowledgment(t, PUBACK)

        send(i/t)

        return i, t, PUBACK
    
    elif (publish_pkt.QOS == 2):
        
        #IF STATEMENT ADDED TO CLOSE CONNECTION IF SERVER DISCONNECTS AFTER SENDING PUBLISH QOS2 PACKET
        if ACK.haslayer(MQTTPubrec) == 0: 
            return i, t, ACK

        PUBREC = ACK

        t.flags = "A"
        t.seq = PUBREC.ack
        t = tcp_acknowledgment(t, PUBREC)

        send(i/t)

        #SEND PUBREL
        m = generate_packet("<PUBREL>")
        pubrel_pkt = i/t/m
        
        ans, unans = sr(pubrel_pkt, multi=1, timeout=0.1, retry=3)

        try:
            PUBCOMP = ans[-1][-1]
        except IndexError:
            pubrel_pkt[TCP].flags = "FA"
            return i, t, pubrel_pkt

        #IF STATEMENT ADDED TO CLOSE CONNECTION IF BROKER SENT A PACKET THAT IS NOT PUBCOMP
        if PUBCOMP.haslayer(MQTTPubcomp) == 0: 
            return i, t, PUBCOMP

        t.flags = "A"
        t.seq = PUBCOMP.ack
        t = tcp_acknowledgment(t, PUBCOMP)

        send(i/t)
        return i, t, PUBCOMP


def mqtt_subscribe(i, t, lp):
    
    t.flags = "PA"
    t.seq = lp.ack
    t = tcp_acknowledgment(t, lp)

    while(True):
        try:
            m = generate_packet("<SUBSCRIBE>")
        except UnicodeDecodeError:
            continue
        break

    subscribe_pkt = i/t/m

    ans, unans = sr(subscribe_pkt, multi=1, timeout=0.1, retry=3)
    
    try:
        SUBACK = ans[-1][-1]
    except IndexError:
        subscribe_pkt[TCP].flags = "FA"
        return i, t, subscribe_pkt

    if SUBACK.haslayer(MQTTPublish):
        i, t, lp = respond_publish(i, t, SUBACK)
        return i, t, lp
    else:
        return i, t, SUBACK

def mqtt_unsubscribe(i, t, lp):

    t.flags = "PA" 
    t.seq = lp.ack
    t = tcp_acknowledgment(t, lp)
    
    while(True):
        try:
            m = generate_packet("<UNSUBSCRIBE>")
        except UnicodeDecodeError:
            continue
        break

    unsubscribe_pkt = i/t/m

    ans, unans = sr(unsubscribe_pkt, multi=1, timeout=0.1, retry=3)

    try:
        UNSUBACK = ans[-1][-1]
    except IndexError:
        unsubscribe_pkt[TCP].flags = "FA"
        return i, t, unsubscribe_pkt
       
    if UNSUBACK.haslayer(MQTTPublish):
        i, t, UNSUBACK = respond_publish(i, t, UNSUBACK)

    #IF STATEMENT ADDED TO CLOSE CONNECTION IF BROKER SENT A PACKET THAT IS NOT UNSUBACK
    if UNSUBACK.haslayer(MQTTUnsuback) == 0: 
        return i, t, UNSUBACK

    #ACKNOWLEDGING RECEIVING UNSUBACK packet
    t.flags = "A"
    t.seq = UNSUBACK.ack
    t = tcp_acknowledgment(t, UNSUBACK)

    send(i/t)
    return i, t, UNSUBACK

def mqtt_ping(i, t, lp):

    t.flags = "PA" 
    t.seq = lp.ack
    t = tcp_acknowledgment(t, lp)

    m = generate_packet("<PINGREQ>")
    pingreq_pkt = i/t/m

    ans, unans = sr(pingreq_pkt, multi=1, timeout=0.1, retry=3)
    
    try:
        PINGRESP = ans[-1][-1]
    except IndexError:
        pingreq_pkt[TCP].flags = "FA"
        return i, t, pingreq_pkt

    if PINGRESP.haslayer(MQTTPublish):
        i, t, PINGRESP = respond_publish(i, t, PINGRESP)

    #IF STATEMENT ADDED TO CLOSE CONNECTION IF BROKER SENT A PACKET THAT IS NOT PINGRESP
    if PINGRESP.haslayer(MQTT) == 0: 
        PINGRESP[TCP].flags = "FA"
        return i, t, PINGRESP

    #ACKNOWLEDGING RECEIVING PINGRESP packet
    t.flags = "A"
    t.seq = PINGRESP.ack
    t = tcp_acknowledgment(t, PINGRESP)

    send(i/t)
    return i, t, PINGRESP


def mqtt_disconnect(i, t, lp):

    t.flags = "FA"
    t.seq = lp.ack
    t = tcp_acknowledgment(t, lp)

    m = generate_packet("<DISCONNECT>")

    ans, unans = sr(i/t/m, multi=1, timeout=0.1, retry=3)
    
    try:
        DISCONNECT_ACK = ans[-1][-1]
    except IndexError:
        lp[TCP].flags = "FA"
        return i, t, lp

    return i, t, DISCONNECT_ACK

def tcp_disconnect(i, t, lp):

    t.flags = "FA"
    t.seq = lp.ack
    t.ack = lp.seq + 1
    send(i/t)

if __name__ == '__main__':
    print("Usage: python3 fuzz.py")
