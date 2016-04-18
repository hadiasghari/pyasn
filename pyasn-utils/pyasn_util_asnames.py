#!/usr/bin/python

# Copyright (c) 2016 Italo Maia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import parsel
import codecs
import argparse
from sys import version_info

try:
    import ujson as json
except ImportError:
    import json

if version_info[0] < 3:
    from urllib2 import urlopen
else:
    from urllib.request import urlopen


ASNAMES_URL = 'http://www.cidr-report.org/as2.0/autnums.html'


def get_parser():
    parser = argparse.ArgumentParser(description='pyasn asnames downloader')
    parser.add_argument(
        '-i', '--html-input', dest='input',
        help='input html file with asnames')
    parser.add_argument(
        '-o', '--output', dest='output',
        help='output file name (defaults to console)')
    return parser


def main(args):
    data = None

    # html source available?
    if args.input:
        with codecs.open(args.input, encoding="utf-8") as fs:
            data = fs.read()

    # data is not available yet? Let's download it!
    if data is None:
        data = download_asnames()

    # parse it to json
    data_dict = _html_to_dict(data)
    data_json = json.dumps(data_dict)

    # output to file?
    if args.output:
        with codecs.open(args.output, 'w', encoding="utf-8") as fs:
            fs.write(data_json)
    else:
        # defaults to console
        print(data_json)


def __parse_asname_line(line):
    sel = parsel.Selector(text=line)
    as_identifier = sel.css("a::text").extract_first().strip()
    as_number = as_identifier[2:].strip()
    split = line.split("</a>")
    as_name = split[-1].strip()
    return as_number, as_name


def _html_to_dict(data):
    """
    Translates an HTML string available at `ASNAMES_URL` into a dict

    :param data:
    :type data: str
    :return:
    :rtype: dict
    """
    sel = parsel.Selector(text=data)
    content = sel.css("pre").extract_first()
    content = content[5:-6]
    fn = __parse_asname_line
    lines = content.split("\n")
    clean_lines = filter(lambda line: line.strip(), lines)
    lines_with_links = filter(lambda line: line.startswith('<a'), clean_lines)
    return dict(map(fn, lines_with_links))


def download_asnames():
    http = urlopen(ASNAMES_URL)
    data = http.read()
    http.close()

    raw_data = data.decode('latin-1')
    raw_data = raw_data.encode('utf-8')
    return raw_data.decode("utf-8")


if __name__ == '__main__':
    parser = get_parser()
    args = parser.parse_args()
    main(args)
