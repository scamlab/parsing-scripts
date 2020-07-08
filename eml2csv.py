# -*- coding: utf-8 -*-

from email import policy
from email.parser import BytesParser
import os
import csv
import sys
from dateutil import parser

arguments = len(sys.argv) - 1

if arguments < 1:
    print("Please add filename as the first argument")
    exit()

input_file = sys.argv[1]

if os.path.isfile(input_file) and os.access(input_file, os.R_OK):
    pass
    # print("File exists and is readable")
else:
    print("Either the file is missing or not readable")

fieldnames = ['datetime', 'scammer-email', 'scammer-name', 'victim-email', 'victim-name', 'subject', 'content',
              'category', 'researcher', 'process-description', 'result', 'filename']

with open(input_file, 'rb') as fp:
    msg = BytesParser(policy=policy.default).parse(fp)
    # txt = msg.get_body(preferencelist=('plain')).get_content()

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition'))

            # skip any text/plain (txt) attachments
            if content_type == 'text/plain' and 'attachment' not in content_disposition:
                body = part.get_payload(decode=True)  # decode
                break
    # not multipart - i.e. plain text, no attachments, keeping fingers crossed
    else:
        body = msg.get_payload(decode=True)

    received = msg['Received']
    received_datetime = received[received.rindex(';'):]
    datetime = parser.parse(received_datetime)
    from_line = msg['from']
    from_line_address_start = from_line.find("<")
    if from_line_address_start != -1:
        from_name = from_line[:from_line_address_start-1]
        from_address = from_line[from_line_address_start+1:-1]
    else:
        from_name = ""
        from_address = from_line

    to_line = msg['to']
    to_line_address_start = to_line.find("<")
    if to_line_address_start != -1:
        to_name = to_line[:to_line_address_start-1]
        to_address = to_line[to_line_address_start+1:-1]
    else:
        to_name = ""
        to_address = to_line

    # print('Subject:', msg['subject'])
    # print('Items:', msg.items())
    # print('Txt:', txt)
    csv_output = csv.DictWriter(sys.stdout, fieldnames=fieldnames, dialect='excel', lineterminator='\n')
    csv_output.writeheader()
    csv_output.writerow({'datetime': datetime, 'scammer-email': from_address, 'scammer-name': from_name,
                         'victim-email': to_address, 'victim-name': to_name, 'subject': msg['subject'],
                         'content': body, 'filename': input_file})


