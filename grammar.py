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
MQTT_GRAMMAR = {
        "<start>":
            ["<packets>"],

        "<packets>":
            [
                "<CONNECT>",
                "<CONNACK>",
                "<PUBLISH>",
                "<PUBACK>",
                "<PUBREC>",
                "<PUBREL>",
                "<PUBCOMP>",
                "<SUBSCRIBE>",
                "<SUBACK>",
                "<UNSUBSCRIBE>",
                "<UNSUBACK>",
                "<PINGREQ>",
                "<PINGRESP>",
                "<DISCONNECT>"
            ],

        "<CONNECT>":#PAYLOAD IS REQUIRED FOR CONNECT PACKETS
        [
           r'\x1<reserved-0><remaining-length><CONNECT_VARIABLE_HEADER_FLAGS_DEFAULTPAYLOAD><CONNECT_DEFAULTPAYLOAD>',
           r'\x1<reserved-0><remaining-length><CONNECT_VARIABLE_HEADER_FLAGS_WILLFLAG><CONNECT_PAYLOAD_WILLTOPIC>',
           r'\x1<reserved-0><remaining-length><CONNECT_VARIABLE_HEADER_FLAGS_USERNAMEFLAG><CONNECT_PAYLOAD_USERNAME>',
           r'\x1<reserved-0><remaining-length><CONNECT_VARIABLE_HEADER_FLAGS_USERNAMEFLAG_WILLFLAG><CONNECT_PAYLOAD_USERNAME_WILLTOPIC>',
           r'\x1<reserved-0><remaining-length><CONNECT_VARIABLE_HEADER_FLAGS_PASSWORDFLAG><CONNECT_PAYLOAD_PASSWORD>',
           r'\x1<reserved-0><remaining-length><CONNECT_VARIABLE_HEADER_FLAGS_USERNAMEFLAG_PASSWORDFLAG_WILLFLAG><CONNECT_PAYLOAD_USERNAME_PASSWORD_WILLTOPIC>',
        ],

        "<CONNECT_VARIABLE_HEADER_FLAGS_DEFAULTPAYLOAD>":
        [r'<protocol-name-length><protocol-name><protocol-version>\x<connect-flags-defaultpayload><keep-alive>'],

        "<CONNECT_VARIABLE_HEADER_FLAGS_WILLFLAG>":
        [r'<protocol-name-length><protocol-name><protocol-version>\x<connect-flags-willflag><keep-alive>'],

        "<CONNECT_VARIABLE_HEADER_FLAGS_USERNAMEFLAG>":
        [r'<protocol-name-length><protocol-name><protocol-version>\x<connect-flags-usernameflag><keep-alive>'],

        "<CONNECT_VARIABLE_HEADER_FLAGS_USERNAMEFLAG_WILLFLAG>":
        [r'<protocol-name-length><protocol-name><protocol-version>\x<connect-flags-usernameflag-willflag><keep-alive>'],

        "<CONNECT_VARIABLE_HEADER_FLAGS_PASSWORDFLAG>":
        [r'<protocol-name-length><protocol-name><protocol-version>\x<connect-flags-passwordflag><keep-alive>'],

        "<CONNECT_VARIABLE_HEADER_FLAGS_USERNAMEFLAG_PASSWORDFLAG_WILLFLAG>":
        [r'<protocol-name-length><protocol-name><protocol-version>\x<connect-flags-usernameflag-passwordflag-willflag><keep-alive>'],

        "<CONNECT_DEFAULTPAYLOAD>": #CLIENTID MUST BE PRESENT IN ALL CONNECT PACKETS
        ["<string-length><client-id>"],

        "<CONNECT_PAYLOAD_WILLTOPIC>": #CLIENTID MUST BE PRESENT IN ALL CONNECT PACKETS
        ["<string-length><client-id><string-length><will-topic><string-length><will-message>"],

        "<CONNECT_PAYLOAD_USERNAME>": #CLIENTID MUST BE PRESENT IN ALL CONNECT PACKETS
        ["<string-length><client-id><string-length><username>"],

        "<CONNECT_PAYLOAD_USERNAME_WILLTOPIC>": #CLIENTID MUST BE PRESENT IN ALL CONNECT PACKETS
        ["<string-length><client-id><string-length><will-topic><string-length><will-message><string-length><username>"],

        "<CONNECT_PAYLOAD_PASSWORD>": #CLIENTID MUST BE PRESENT IN ALL CONNECT PACKETS
        ["<string-length><client-id><string-length><username><string-length><password>"],

        "<CONNECT_PAYLOAD_USERNAME_PASSWORD_WILLTOPIC>": #CLIENTID MUST BE PRESENT IN ALL CONNECT PACKETS
        ["<string-length><client-id><string-length><will-topic><string-length><will-message><string-length><username><string-length><password>"],

        "<CONNACK>": #HAS NO PAYLOAD
        [r'\x2<reserved-0>\x02<CONNACK_VARIABLE_HEADER>'],

        "<CONNACK_VARIABLE_HEADER>":
        [r'<connack-flags><session-present-flag>\x<connect-return-code>'],

        "<connack-flags>":
        [r'\x0'], #MUST BE 0
                
        "<session-present-flag>": #DEPENDS ON CONNECT PACKET (CLEANSESS ENABLED)
        [
            "0", #NOT ENABLED
            "1" #ENABLED
        ],

        "<connect-return-code>":
        [
            "00", #CONNECTION ACCEPTED
            "01", #CONNECTION REFUSED UNACCEPTABLE PROTOCOL VERSION
            "02", #CONNECTION REFUSED IDENTIFIER REJECTED
            "03", #CONNECTION REFUSED SERVER UNAVAILABLE
            "04", #CONNECTION REFUSED BAD USERNAME OR PASSWORD
            "05", #CONNECTION REFUSED NOT AUTHORIZED
            #6-255 RESERVED FOR FUTURE USE
        ],
            
        "<PUBLISH>": #CAN HAVE A PAYLOAD LENGTH OF ZERO
        [
            r'\x3<PUBLISH_FIXED_HEADER_QOS0><PUBLISH_VARIABLE_HEADER_QOS0>', 
            r'\x3<PUBLISH_FIXED_HEADER_QOS0><PUBLISH_VARIABLE_HEADER_QOS0><PUBLISH_PAYLOAD>',
            r'\x3<PUBLISH_FIXED_HEADER_QOS12><PUBLISH_VARIABLE_HEADER_QOS12>', 
            r'\x3<PUBLISH_FIXED_HEADER_QOS12><PUBLISH_VARIABLE_HEADER_QOS12><PUBLISH_PAYLOAD>'
        ],

        "<PUBLISH_FIXED_HEADER_QOS0>":
        ["<publish-reserved-qos0><remaining-length>"], 

        "<PUBLISH_VARIABLE_HEADER_QOS0>":
        ["<string-length><topic-name>"],

        "<PUBLISH_FIXED_HEADER_QOS12>":
        ["<publish-reserved-qos12><remaining-length>"], 

        "<PUBLISH_VARIABLE_HEADER_QOS12>":
        ["<string-length><topic-name><packet-identifier>"],

        "<PUBLISH_PAYLOAD>":
        ["<message>"],

        "<PUBACK>": #HAS NO PAYLOAD; SENT ONLY IF QOS=1#
        [r'\x4<reserved-0>\x02<PUBACK_VARIABLE_HEADER>'],

        "<PUBACK_VARIABLE_HEADER>":
        ["<packet-identifier>"], #PACKET IDENTIFIER MUST BE SAME AS PUBLISH PACKET

        "<PUBREC>": #HAS NO PAYLOAD; SENT FROM SERVER TO CLIENT IF QOS=2
        [r'\x5<reserved-0>\x02<PUBREC_VARIABLE_HEADER>'],

        "<PUBREC_VARIABLE_HEADER>":
        ["<packet-identifier>"], #PACKET IDENTIFIER MUST BE SAME AS PUBLISH PACKET

        "<PUBREL>": #HAS NO PAYLOAD; SENT ONLY IF QOS=2
        [r'\x6<reserved-2>\x02<PUBREL_VARIABLE_HEADER>'],

        "<PUBREL_VARIABLE_HEADER>":
        ["<packet-identifier>"], #PACKET IDENTIFIER MUST BE SAME AS PUBLISH PACKET

        "<PUBCOMP>": #HAS NO PAYLOAD, SENT FROM SERVER TO CLIENT IF QOS=2
        [r'\x7<reserved-0>\x02<PUBCOMP_VARIABLE_HEADER>'],

        "<PUBCOMP_VARIABLE_HEADER>":
        ["<packet-identifier>"], #PACKET IDENTIFIER MUST BE SAME AS PUBLISH PACKET

        "<SUBSCRIBE>": #PAYLOAD IS REQUIRED! #RESERVED MUST BE SET TO 0,0,1,0 (2) respectively, otherwise server must close connection.
        [r'\x8<reserved-2><remaining-length><SUBSCRIBE_VARIABLE_HEADER><SUBSCRIBE_PAYLOAD>'],

        "<SUBSCRIBE_VARIABLE_HEADER>":
        ["<packet-identifier>"],

        "<SUBSCRIBE_PAYLOAD>":
        [
            "<string-length><topic-name><subscribe-reserved-qos><SUBSCRIBE_PAYLOAD>", 
            "<string-length><topic-name><subscribe-reserved-qos>"
        ], 

        "<SUBACK>": #PAYLOAD IS REQUIRED!
        [r'\x9<reserved-0><remaining-length><SUBACK_VARIABLE_HEADER>\x<SUBACK_PAYLOAD>'],

        "<SUBACK_VARIABLE_HEADER>":
        ["<packet-identifier>"], #PACKET IDENTIFIER MUST BE SAME AS SUBSCRIBE PACKET

        "<SUBACK_PAYLOAD>":
        [
            "00", #SUCCESS - MAXIMUM QOS0
            "01", #SUCCESS - MAXIMUM Q0S1
            "02", #SUCCESS - MAXIMUM QOS2
            "80", #FAILURE
        ],

        "<UNSUBSCRIBE>": #PAYLOAD IS REQUIRED! #RESERVED MUST BE SET TO 0,0,1,0 respectively, otherwise server must close connection.
        [r'\xa<reserved-2><remaining-length><UNSUBSCRIBE_VARIABLE_HEADER><UNSUBSCRIBE_PAYLOAD>'],

        "<UNSUBSCRIBE_VARIABLE_HEADER>":
        ["<packet-identifier>"],

        "<UNSUBSCRIBE_PAYLOAD>":
        [
            "<string-length><topic-name><UNSUBSCRIBE_PAYLOAD>",
            "<string-length><topic-name>"
        ],

        "<UNSUBACK>": #HAS NO PAYLOAD
        [r'\xb<reserved-0>\x02<UNSUBACK_VARIABLE_HEADER>'],

        "<UNSUBACK_VARIABLE_HEADER>":
        ["<packet-identifier>"], #PACKET IDENTIFIER MUST BE SAME AS UNSUBSCRIBE PACKET

        "<PINGREQ>": #PINGREQ DOES NOT HAVE VARIABLE HEADER NOR PAYLOAD.  #FIXED HEADER: #1. MQTT CONTROL PACKET TYPE (12) #2. RESERVED (NOT SPECIFIED) #3. REMAINING LENGTH (0)
        [r'\xc<reserved-0>\00'],

        "<PINGRESP>": #PINGRESP DOES NOT HAVE VARIABLE HEADER NOR PAYLOAD.  #FIXED HEADER: #1. MQTT CONTROL PACKET TYPE (13) #2. RESERVED (NOT SPECIFIED) #3. REMAINING LENGTH (0)
        [r'\xd<reserved-0>\00'],

        "<DISCONNECT>": #DISCONNECT DOES NOT HAVE VARIABLE HEADER NOR PAYLOAD.  #FIXED HEADER: #1. MQTT CONTROL PACKET TYPE (14) #2. RESERVED (0) #3. REMAINING LENGTH (0)
        [r'\xe0\00'],

        "<hexdigit>":
        [
            "0", 
            "1",
            "2",
            "3", 
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "a",
            "b",
            "c",
            "d",
            "e",
            "f"
        ], 

        "<digit>":
        [ 
            "0", 
            "1", 
            "2", 
            "3", 
            "4", 
            "5", 
            "6", 
            "7", 
            "8", 
            "9"
        ],
        
        "<reserved-0>":
        ["0"], 
        
        "<reserved-2>":
        ["2"], 
        
        "<protocol-name-length>": #4
        [r'\x00\x04'],

        "<protocol-name>": #MQTT
        [r'\x4d\x51\x54\x54'],

        "<protocol-version>": #Version 3.1.1
        [
            r'\x04',
        ],

        "<connect-flags>":
        [
            "00", #NO FLAGS ENABLED
            "02", #RESERVED DISABLED CLEANSESS ENABLED
            "04", # WILL FLAG ENABLED EVERYTHING ELSE DISABLED
            "06", # WILL FLAG ENABLED CLEANSESS ENABLED
            "08", # WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED 
            "0a", #WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED CLEANSESS ENABLED
            "0c", #WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED WILL FLAG ENABLED 
            "0e", #WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "10", #WILLQOSFLAG=EXACTLY ONCE DELIVERY
            "12", #WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
            "14", #WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
            "16", #WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
            "20", #WILLRETAINFLAG=ENABLED 
            "22", #WILLRETAINFLAG=ENABLED CLEANSESS ENABLED
            "24", #WILLRETAINFLAG=ENABLED WILL FLAG ENABLED
            "26", #WILLRETAINFLAG=ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "28", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED
            "2a", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED CLEANSESS ENABLED
            "2c", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED WILL FLAG ENABLED
            "2f", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "30", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY
            "32", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERYCLEANSESS ENABLED
            "34", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERYWILL FLAG ENABLED
            "36", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERYWILL FLAG ENABLED CLEANSESS ENABLED
            "80", #USERNAME ENABLED
            "82", #USERNAME ENABLED CLEANSESS ENABLED
            "84", #USERNAME ENABLED WILL FLAG ENABLED
            "86", #USERNAME ENABLED WILL FLAG ENABLED CLEANSES ENNABLED
            "88", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED
            "8a", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED CLEANSESS ENABLED
            "8c", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED WILL FLAG ENABLED
            "8e", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "90", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY 
            "92", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
            "94", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
            "96", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
            "a0", #USERNAME ENABLED WILLRETAINFLAG=ENABLED
            "a2", #USERNAME ENABLED WILLRETAINFLAG=ENABLED CLEANSESS ENABLED
            "a4", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILL FLAG ENABLED
            "a6", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "a8", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY
            "aa", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY CLEANSESS ENABLED
            "ac", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILL FLAG ENABLED
            "ae", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
            "b0", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY 
            "b2", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
            "b4", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
            "b6", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
            "c0", #USERNAME ENABLED PASSWORD ENABLED
            "c2", #USERNAME ENABLED PASSWORD ENABLED CLEANSESS ENABLED
            "c4", #USERNAME ENABLED PASSWORD ENABLED WILL FLAG ENABLED
            "c6", #USERNAME ENABLED PASSWORD ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "c8", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED
            "ca", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY CLEANSESS ENABLED
            "cc", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG ENABLED
            "ce", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG=ENABLED CLEANSESS ENABLED
            "d0", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY
            "d2", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
            "d4", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
            "d6", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
            "e0", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED
            "e2", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLEDCLEANSESS ENABLED
            "e4", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILL FLAG ENABLED
            "e6", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "e8", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY
            "ea", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLEDWILLQOSFLAG=AT LEAST ONCE DELIVERY CLEANSESS ENABLED
            "ec", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLEDWILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG ENABLED
            "ee", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG ENABLED CLEANSESS ENABLED
            "f0", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY
            "f2", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY CLEANSESS ENABLED
            "f4", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVER WILL FLAG ENABLED
            "f6", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED

        ],

        "<connect-flags-defaultpayload>": #IF the will flag is set to 0, the will QoS and will retain fields in the connect flags must be set to zero.
        [
            "00",
            "02", #RESERVED DISABLED CLEANSESS ENABLED
        ],

        "<connect-flags-willflag>": #If the will flag is set to 1, the will QoS and will retain fields in the connect flags will be used by the server.
        [
            "04", # WILL FLAG ENABLED EVERYTHING ELSE DISABLED
            "06", # WILL FLAG ENABLED CLEANSESS ENABLED
            "0c", #WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED WILL FLAG ENABLED 
            "0e", #WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "14", #WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
            "16", #WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
            "24", #WILLRETAINFLAG=ENABLED WILL FLAG ENABLED
            "26", #WILLRETAINFLAG=ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "2c", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY ENABLED WILL FLAG ENABLED
            "2f", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "34", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERYWILL FLAG ENABLED
            "36", #WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERYWILL FLAG ENABLED CLEANSESS ENABLED
        ], 

        "<connect-flags-usernameflag>":
        [

            #if WILLFLAG==0, THEN WILLQOS=0
            #IF WILLFLAG==1, THEN WILLQOS=0, 1, OR 2
            #IF WILLFLAG==0, THEN WILLRETAIN=0
            #IF WILLFLAG==1, THEN WILLRETAIN=0, OR 1
            "80", #USERNAME ENABLED
            "82", #USERNAME ENABLED CLEANSESS ENABLED
        ],
            
        "<connect-flags-usernameflag-willflag>":
        [
            "84", #USERNAME ENABLED WILL FLAG ENABLED
            "86", #USERNAME ENABLED WILL FLAG ENABLED CLEANSES ENNABLED
            "8c", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED WILL FLAG ENABLED
            "8e", #USERNAME ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERED ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "94", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
            "96", #USERNAME ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
            "a4", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILL FLAG ENABLED
            "a6", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "ac", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILL FLAG ENABLED
            "ae", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
            "b4", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
            "b6", #USERNAME ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
        ],
             
        "<connect-flags-passwordflag>":
        [

            #if WILLFLAG==0, THEN WILLQOS=0
            #IF WILLFLAG==1, THEN WILLQOS=0, 1, OR 2
            #IF WILLFLAG==0, THEN WILLRETAIN=0
            #IF WILLFLAG==1, THEN WILLRETAIN=0, OR 1
            "c0", #USERNAME ENABLED PASSWORD ENABLED
            "c2", #USERNAME ENABLED PASSWORD ENABLED CLEANSESS ENABLED
        ],
            
        "<connect-flags-usernameflag-passwordflag-willflag>":
        [

            "c4", #USERNAME ENABLED PASSWORD ENABLED WILL FLAG ENABLED
            "c6", #USERNAME ENABLED PASSWORD ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "cc", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG ENABLED
            "ce", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG=ENABLED CLEANSESS ENABLED
            "d4", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED
            "d6", #USERNAME ENABLED PASSWORD ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
            "e4", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILL FLAG ENABLED
            "e6", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILL FLAG ENABLED CLEANSESS ENABLED
            "ec", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLEDWILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG ENABLED
            "ee", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=AT LEAST ONCE DELIVERY WILLFLAG ENABLED CLEANSESS ENABLED
            "f4", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVER WILL FLAG ENABLED
            "f6", #USERNAME ENABLED PASSWORD ENABLED WILLRETAINFLAG=ENABLED WILLQOSFLAG=EXACTLY ONCE DELIVERY WILL FLAG ENABLED CLEANSESS ENABLED
        ],

        "<keep-alive>":
        [r'\x<hexdigit><hexdigit>\x<hexdigit><hexdigit>'],

        "<client-id>":#1-23 CHARACTERS
        [
            "<utf8-numbers><client-id>",
            "<utf8-numbers>",
            "<utf8-latin-capitalletters><client-id>",
            "<utf8-latin-capitalletters>",
            "<utf8-latin-smallletters><client-id>",
            "<utf8-latin-smallletters>"
        ], 

        "<will-topic>":
        [
            "<utf8-characters><will-topic>",
            "<utf8-characters>"
        ],

        "<will-message>":
        [
            "<utf8-characters><will-message>",
            "<utf8-characters>"
        ],

        "<username>":
        [
            "<utf8-characters><username>",
            "<utf8-characters>"
        ],

        "<password>":
        [
            "<utf8-characters><password>",
            "<utf8-characters>"
        ],

        "<publish-reserved-qos0>":
        [
            "1", #DUP:0 QOS:0 RETAIN:0
        ],

        "<publish-reserved-qos12>":
        [
            "2", #DUP:0 QOS:1 RETAIN:0
            "3", #DUP:0 QOS:1 RETAIN:1
            "a", #DUP:1 QOS:1 RETAIN:0
            "b", #DUP:1 QOS:1 RETAIN:1
            "4", #DUP:0 QOS:2 RETAIN:0
            "5", #DUP:0 QOS:2 RETAIN:1
            "c", #DUP:1 QOS:2 RETAIN:0
            "d"  #DUP:1 QOS:2 RETAIN:1
        ],

        "<subscribe-reserved-qos>":
        [
            r'\x00', 
            r'\x01', 
            r'\x02'
        ],

        "<topic-name>":
        [
            "<utf8-characters><topic-name>",
            "<utf8-characters>",
            r'<topic-name>\x2f<topic-name>'
        ],

        "<message>":
        [
            "<utf8-characters><message>",
            "<utf8-characters>"
        ],

        "<packet-identifier>":
        [r'\x<digit><digit>\x<digit><digit>'],

        "<utf8-characters>":
        [
            "<utf8-numbers>", 
            "<utf8-latin-capitalletters>", 
            "<utf8-latin-smallletters>", 
            "<utf8-symbols>"
        ],

        "<utf8-numbers>":
        [
            r'\x30', 
            r'\x31', 
            r'\x32', 
            r'\x33', 
            r'\x34', 
            r'\x35', 
            r'\x36', 
            r'\x37', 
            r'\x38', 
            r'\x39'
        ],

        "<utf8-latin-capitalletters>":
        [
            r'\x41', 
            r'\x42', 
            r'\x43', 
            r'\x44', 
            r'\x45', 
            r'\x46', 
            r'\x47', 
            r'\x48', 
            r'\x49', 
            r'\x4a', 
            r'\x4b', 
            r'\x4c', 
            r'\x4d', 
            r'\x4e', 
            r'\x4f', 
            r'\x50', 
            r'\x51', 
            r'\x52', 
            r'\x53', 
            r'\x54', 
            r'\x55', 
            r'\x56', 
            r'\x57', 
            r'\x58', 
            r'\x59', 
            r'\x5a'
        ],
        
        "<utf8-latin-smallletters>":
        [
            r'\x61', 
            r'\x62', 
            r'\x63', 
            r'\x64', 
            r'\x65', 
            r'\x66', 
            r'\x67', 
            r'\x68', 
            r'\x69', 
            r'\x6a', 
            r'\x6b', 
            r'\x6c', 
            r'\x6d', 
            r'\x6e', 
            r'\x6f', 
            r'\x70', 
            r'\x71', 
            r'\x72', 
            r'\x73', 
            r'\x74', 
            r'\x75', 
            r'\x76', 
            r'\x77', 
            r'\x78', 
            r'\x79', 
            r'\x7a'
        ],

        "<utf8-symbols>":
        [
            r'\x20', 
            r'\x21', 
            r'\x22', 
            r'\x23', 
            r'\x24', 
            r'\x25', 
            r'\x26', 
            r'\x27', 
            r'\x28', 
            r'\x29', 
            r'\x2a', 
            r'\x2b', 
            r'\x2c', 
            r'\x2d', 
            r'\x2e', 
            r'\x2f', 
            r'\x3a', 
            r'\x3b', 
            r'\x3c', 
            r'\x3d', 
            r'\x3e', 
            r'\x3f', 
            r'\x40', 
            r'\x5b', 
            r'\x5c', 
            r'\x5d', 
            r'\x5e', 
            r'\x5f', 
            r'\x60', 
            r'\x7b', 
            r'\x7c', 
            r'\x7d', 
            r'\x7e', 
            r'\xc2\xa0', 
            r'\xc2\xa1', 
            r'\xc2\xa2', 
            r'\xc2\xa3', 
            r'\xc2\xa4', 
            r'\xc2\xa5', 
            r'\xc2\xa6', 
            r'\xc2\xa7', 
            r'\xc2\xa8', 
            r'\xc2\xa9', 
            r'\xc2\xaa', 
            r'\xc2\xab', 
            r'\xc2\xac', 
            r'\xc2\xad', 
            r'\xc2\xae', 
            r'\xc2\xaf', 
            r'\xc2\xb0', 
            r'\xc2\xb1', 
            r'\xc2\xb2', 
            r'\xc2\xb3', 
            r'\xc2\xb4', 
            r'\xc2\xb5', 
            r'\xc2\xb6', 
            r'\xc2\xb7', 
            r'\xc2\xb8', 
            r'\xc2\xb9', 
            r'\xc2\xba', 
            r'\xc2\xbb', 
            r'\xc2\xbc', 
            r'\xc2\xbd', 
            r'\xc2\xbe', 
            r'\xc2\xbf'
        ],


        "<remaining-length>":
        [r'\t'], 

        "<string-length>":
        [r'\n\n'],

}
