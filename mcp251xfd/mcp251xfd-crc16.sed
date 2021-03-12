#!/bin/bash

#sed -e "s/.*CRC read error at address 0x0\(.\)\(..\) (length=\(.\), data=\(..\) \(..\) \(..\) \(..\), CRC=0x\(..\)\(..\)) retrying./{ .cmd = { 0xb\1, 0x\2, }, .len = 0x\3, .data = { 0x\4, 0x\5, 0x\6, 0x\7, }, .crc = { 0x\8, 0x\9 }, },/"a

sed -ne "s/.*CRC read error at address 0x\(..\)\(..\) (length=\(.\), data=\(..\) \(..\) \(..\) \(..\), CRC=0x\(..\)\(..\)) retrying./0x\1, 0x\2, 0x\3, 0x\4, 0x\5, 0x\6, 0x\7, 0x\8, 0x\9/p"
