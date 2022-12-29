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
from scapy.contrib.mqtt import *
from scapy.all import *
import random
from grammar import MQTT_GRAMMAR

RE_NONTERMINAL = re.compile(r'(<[^<> ]*>)')

def calculate_remaining_length(byte_string):
    packet = MQTT(byte_string)
    packet.len = len(packet) - 2 #Remaining length: length of packet excluding the fixed header
    return packet

def convert_string_to_bytes(term):
    term_bytes = term.encode('utf-8')
    byte_string = bytes(map(ord, term_bytes.decode('unicode-escape')))
    return byte_string


def calculate_field_lengths(term, payload_length, packet_identifier):
    substr = re.findall(r'\\n\\n(.*)', term)
    if len(substr) > 0:
        fields = re.split(r'\\n\\n', substr[0])
        #print(fields)

        for field in fields:
            field_encoded = field.encode('utf-8')
            field_bytes = bytes(map(ord, field_encoded.decode('unicode-escape')))
            
            #IF STATEMENT ADDED TO SPECIFY EXACTLY THE TOPIC LENGTH, AND THUS RECOGNIZE THE PAYLOAD CORRECTLY
            if term[2] == "3" and field == fields[-1]: #Check whether it is a PUBLISH packet
                field_length = struct.pack(">H", len(field_bytes) - payload_length - packet_identifier)

            elif term[2] == "8": #Check whether it is a SUBSCRIBE packet
                field_length = struct.pack(">H", len(field_bytes) - 1)# Subtract topic - QoS length

            else:
                field_length = struct.pack(">H", len(field_bytes))

            field_length_bytes = field_length.decode("utf-8") 
            term = term.replace(r'\n\n', field_length_bytes, 1)

    return term

def apply_expansion(symbol_to_expand, expansion, expansion_trials, term, payload_length, packet_identifier):
    
    new_term = term.replace(symbol_to_expand, expansion, 1)
        
    if "<message>" in expansion:
        payload_length+=1
    elif "<packet-identifier>" in expansion:
        packet_identifier=2

    if len(nonterminals(new_term)) < 50: #was  < 10. needed to modify for connect
        term = new_term
        #print("%-40s" % (symbol_to_expand + " -> " + expansion), term)
        expansion_trials = 0
    else:
        expansion_trials += 1
        if expansion_trials >= 100:
            raise ExpansionError("Cannot expand " + repr(term))
        
    return term, expansion_trials, payload_length, packet_identifier

def choose_expansion_rule(symbol_to_expand):
    expansions = MQTT_GRAMMAR[symbol_to_expand]
    expansion = random.choice(expansions)
    return expansion

def choose_nonterminal(term):
    symbol_to_expand = random.choice(nonterminals(term))
    return symbol_to_expand

def nonterminals(expansion):
    if isinstance(expansion, tuple):
        expansion = expansion[0]
    return re.findall(RE_NONTERMINAL, expansion)

def generate_packet(term):
    #term = "<start>"
    payload_length=0
    packet_identifier=0
    expansion_trials=0

    while len(nonterminals(term)) > 0:
        symbol_to_expand=choose_nonterminal(term)
        expansion=choose_expansion_rule(symbol_to_expand)
        term, expansion_trials, payload_length, packet_identifier=apply_expansion(symbol_to_expand, expansion, expansion_trials, term, payload_length, packet_identifier)
    
    term=calculate_field_lengths(term, payload_length, packet_identifier)
    byte_string=convert_string_to_bytes(term)
    packet=calculate_remaining_length(byte_string)

    return packet

if __name__ == '__main__':
    print("Usage: python3 fuzz.py")
