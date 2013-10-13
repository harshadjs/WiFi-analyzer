#!/bin/bash

PCAP_FILE=$1
BSSID=$2
TMP_CSV_FILE=/tmp/${PCAP_FILE}.csv

analyze()
{
    if [ "$2" = "prism" ]; then
	proto=p
    else
	proto=r
    fi
    chmod +rw $TMP_CSV_FILE
    ./wifi_analyzer -i $1 -p $proto -b $BSSID
#    rm $TMP_CSV_FILE
}


if [ "$1" = "" -o "$2" = "" ]; then
    echo "Usage: $0 <pcap_file> <bssid>"
    exit
fi

# Check if tshark is installed
hash tshark 2>/dev/null
if [ "$?" != "0" ]; then
    echo "tshark is not installed. Run the following command to install it:"
    echo "sudo apt-get install tshark"
    exit
fi

HEADER_TYPE=`tshark -r ${PCAP_FILE} -T fields -e frame.number -e frame.protocols frame.number==1 -E separator="," | cut -d "," -f2 | cut -d ":" -f1`

echo -ne "Exporting to csv ... "
if [ "$HEADER_TYPE" = "prism" ] ; then
    tshark -r $PCAP_FILE -T fields -e wlan.fc.type_subtype -e prism.did.hosttime -e prism.did.rate -e prism.did.frmlen -e wlan.da -e wlan.bssid -e wlan.sa -e wlan.ra -e wlan.fc.retry -E separator=',' > $TMP_CSV_FILE
    if [ "$?" = "0" ] ; then
	echo "[DONE]"
	analyze $TMP_CSV_FILE $HEADER_TYPE
	exit
    else
	echo "pcap can't be exported to CSV."
	exit
    fi
elif [ "$HEADER_TYPE" = "radiotap" ] ; then
    tshark -r $PCAP_FILE -T fields -e wlan.fc.type_subtype -e "dummy" -e radiotap.mactime -e "dummy" -e radiotap.datarate -e frame.len -e wlan.da -e wlan.bssid -e wlan.sa -e wlan.ra -e wlan.fc.retry -E separator=',' > $TMP_CSV_FILE
    if [ "$?" = "0" ] ; then
	echo "Successfully created CSV file : $TMP_CSV_FILE"
	exit
    else
	echo "Failure while creating CSV file"
	exit
    fi
else
    echo "Unrecognized header type"
fi
