# -*- coding: utf-8 -*-

from email import policy
from email.parser import BytesParser
import os
import csv
import sys
from dateutil import parser
import sqlite3

conn = sqlite3.connect('scamlab.db')

c = conn.cursor()

# get the count of tables with the name
c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='scams' ''')

# if the count is 0, then tables need to be created
if c.fetchone()[0] == 0:
    # Create table
    c.execute('''CREATE TABLE scams (id integer, parent_id integer, datetime text, scammer_email text, scammer_name text, victim_email text, 
    victim_name text, subject text, content text, category_id integer, researcher_id integer, comments text, 
    result text, filename text, source text)''')
# 'datetime', 'scammer-email', 'scammer-name', 'victim-email', 'victim-name', 'subject', 'content',
#               'category', 'researcher', 'process-description', 'result', 'filename', 'source'


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
              'category', 'researcher', 'process-description', 'result', 'filename', 'source']

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
        from_name = from_line[:from_line_address_start - 1]
        from_address = from_line[from_line_address_start + 1:-1]
    else:
        from_name = ""
        from_address = from_line

    to_line = msg['to']
    to_line_address_start = to_line.find("<")
    if to_line_address_start != -1:
        to_name = to_line[:to_line_address_start - 1]
        to_address = to_line[to_line_address_start + 1:-1]
    else:
        to_name = ""
        to_address = to_line

    fp.seek(0)
    source = fp.read()

    csv_output = csv.DictWriter(sys.stdout, fieldnames=fieldnames, dialect='excel', lineterminator='\n')
    csv_output.writeheader()
    csv_output.writerow({'datetime': datetime, 'scammer-email': from_address, 'scammer-name': from_name,
                         'victim-email': to_address, 'victim-name': to_name, 'subject': msg['subject'],
                         'content': body, 'filename': input_file, 'source': source})

    sqlite_insert_with_param = """INSERT INTO scams
                      (datetime, scammer_email, scammer_name, victim_email, victim_name, subject, content, filename,
                       source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);"""

    data_tuple = (datetime, from_address, from_name, to_address, to_name, msg['subject'], body, input_file, source)

    c.execute(sqlite_insert_with_param, data_tuple)

    # Save (commit) the changes
    conn.commit()

# We can also close the connection if we are done with it.
# Just be sure any changes have been committed or they will be lost.
conn.close()
