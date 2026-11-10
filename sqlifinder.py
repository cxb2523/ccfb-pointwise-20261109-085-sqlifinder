import argparse
import logging
import os
import sys
import time

import requests
from huepy import *
from tqdm import tqdm

from core import requester
from core import extractor
from core import crawler
from urllib.parse import unquote

start_time = time.time()
logger = logging.getLogger("sqlifinder")


def clear():
    if 'linux' in sys.platform:
        os.system('clear')
    elif 'darwin' in sys.platform:
        os.system('clear')
    else:
        os.system('cls')


def banner():
    ban = r'''
            ___ ____         __
  ___ ___ _/ (_) _(_)__  ___/ /__ ____
 (_-</ _ `/ / / _/ / _ \/ _  / -_) __/
/___/\_, /_/_/_//_/_//_/\_,_/\__/_/
      /_/        ~ by @americo        v1.0
      '''

    print(green(ban))


def concatenate_list_data(list, result):
    for element in list:
        result = result + "\n" + str(element)
    return result


def error_based_get(uris, payloads):
    """Original response-string based check over GET parameter URLs."""
    hits = []
    for uri in uris:
        for payload in payloads:
            final_url = uri + payload
            try:
                req = requests.get("{}".format(final_url))
                res = req.text
                if 'SQL' in res or 'sql' in res or 'Sql' in res:
                    print("[" + green("sql-injection") + "] " + final_url)
                    hits.append({'method': 'GET', 'url': final_url,
                                 'payload': payload, 'type': 'error-based'})
                    break
            except requests.RequestException:
                pass
    return hits


def error_based_post(form_points, payloads):
    """Response-string based check over POST form injection points."""
    hits = []
    for point in form_points:
        action = point['action']
        for payload in payloads:
            data = dict(point['fields'])
            data[point['target']] = payload
            try:
                res = requests.post(action, data=data).text
            except requests.RequestException:
                continue
            if 'SQL' in res or 'sql' in res or 'Sql' in res:
                label = "%s field=%s" % (action, point['target'])
                print("[" + green("sql-injection") + "] POST " + label)
                hits.append({'method': 'POST', 'url': action,
                             'field': point['target'], 'payload': payload,
                             'type': 'error-based'})
                break
    return hits


def main():
    parser = argparse.ArgumentParser(
        description='sqlifinder - a sql injection scanner tool'
    )
    parser.add_argument('-d', '--domain',
                        help='Domain name of the target [ex. example.com]',
                        required=True)
    parser.add_argument('-s', '--subs',
                        help='Set false or true [ex: --subs False]',
                        default=False)
    parser.add_argument('--time-based', action='store_true',
                        help='Enable time-based blind injection checks '
                             '(baseline + threshold + double confirmation)')
    parser.add_argument('--forms', action='store_true',
                        help='Parse POST forms and test each field as an '
                             'injection point')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S',
    )

    if args.subs == True:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{args.domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
    else:
        url = f"http://web.archive.org/cdx/search/cdx?url={args.domain}/*&output=txt&fl=original&collapse=urlkey&page=/"

    clear()
    banner()

    response = requester.connector(url)
    if response is False:
        # Wayback endpoint unreachable: fall back to locally crawled URLs.
        logger.warning("wayback endpoint unavailable, using crawler results only")
        response = ""
    crawled_pages = crawler.spider_pages(f"http://{args.domain}", 10)
    crawled_urls = [page_url for page_url, _html in crawled_pages]
    response = concatenate_list_data(crawled_urls, response)
    if response == False:
        return
    response = unquote(response)

    print("\n" + "[" + blue("INF") + "]" + f" Scanning sql injection for {args.domain}")

    exclude = ['woff', 'js', 'ttf', 'otf', 'eot', 'svg', 'png', 'jpg']
    final_uris = extractor.param_extract(response, "high", exclude, "")

    regular_payloads, time_payloads = requester.load_payloads('payloads.txt')
    logger.info("loaded %s regular payloads, %s time-based payloads (%s engines)",
                len(regular_payloads),
                sum(len(p) for p in time_payloads.values()),
                ", ".join(time_payloads) or "none")

    vulnerable_urls = []

    # Error-based checks on GET parameters (original behavior, kept intact).
    vulnerable_urls.extend(error_based_get(final_uris, regular_payloads))

    form_points = []
    if args.forms:
        # The same form is usually re-served on every page; dedup points
        # across pages so requests don't multiply with the crawl depth.
        seen_points = set()
        for page_url, html in crawled_pages:
            points = extractor.form_extract(html, page_url)
            for point in points:
                key = (point['action'], point['method'], point['target'],
                       tuple(sorted(point['fields'].items())))
                if key in seen_points:
                    continue
                seen_points.add(key)
                form_points.append(point)
            logger.info("page %s produced %s POST injection point(s) (%s unique total)",
                        page_url, len(points), len(form_points))
        vulnerable_urls.extend(error_based_post(form_points, regular_payloads))

    if args.time_based:
        if not time_payloads:
            logger.warning("no time-based payloads found in payloads.txt, "
                           "skipping time-based scan")
        for uri in final_uris:
            hit = requester.time_based_scan('GET', uri, time_payloads)
            if hit:
                print("[" + green("time-based") + "] " + uri + hit['payload'])
                vulnerable_urls.append(hit)

        for point in form_points:
            hit = requester.time_based_scan(
                'POST', point['action'], time_payloads,
                data=point['fields'], target_field=point['target'],
            )
            if hit:
                print("[" + green("time-based") + "] POST " + point['action']
                      + " field=" + point['target'])
                vulnerable_urls.append(hit)

    print("\n[" + blue("INF") + "] scan finished in %.1fs, %s finding(s)"
          % (time.time() - start_time, len(vulnerable_urls)))
    for finding in vulnerable_urls:
        print("  - %s" % finding)


if __name__ == "__main__":
    clear()
    banner()
    main()
