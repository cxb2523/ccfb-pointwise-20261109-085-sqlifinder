import logging
import random
import statistics
import time

import requests

logger = logging.getLogger("sqlifinder")

# Hard guard so a single injection point can never consume the whole scan.
DEFAULT_MAX_REQUESTS_PER_POINT = 30
DEFAULT_TIME_BUDGET = 240          # seconds, per injection point
DEFAULT_BASELINE_SAMPLES = 4       # within the required 3~5 range
BASELINE_JITTER_RATIO = 0.35       # max spread/median tolerated on baseline
BASELINE_JITTER_FLOOR = 0.25       # absolute allowance (s) for very fast,
                                   # low-median endpoints where ratio is noisy
THRESHOLD_MULTIPLIER = 2.0         # threshold = max(margin, multiplier * median)
THRESHOLD_MARGIN = 2.0             # fixed delay margin in seconds
CONFIRM_HITS = 2                   # consecutive slow requests required to confirm

_USER_AGENT_LIST = [
    #Chrome
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
    #Firefox
    'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 6.2; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
    'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
    'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)'
]


def _headers():
    return {'User-Agent': random.choice(_USER_AGENT_LIST)}


def connector(url):
    """
    Make an HTTP GET request to a URL with a random user agent.

    Args:
        url (str): The target URL to send the GET request to

    Returns:
        str: The response text from the server, or False if connection fails
    """
    try:
        # TODO control request headers in here
        response = requests.get(url, headers=_headers(), timeout=30)
        return response.text
    except requests.ConnectionError:
        logger.error("Can not connect to server. Check your internet connection")
    except requests.Timeout:
        logger.error("Timeout Error requesting %s", url)
    except requests.RequestException:
        logger.error("Error in HTTP request for %s", url)
    except KeyboardInterrupt:
        raise KeyboardInterrupt("Interrupted by user")
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
    return False


def load_payloads(path):
    """
    Load payloads.txt, supporting an optional ``# [time-based]`` section.

    Lines above the marker are returned as regular (error-based) payloads.
    Below the marker, ``# [engine]`` comments group time-based payloads by
    database engine; plain comment/blank lines are ignored. A file without
    any marker loads exactly as before: everything goes to regular payloads.

    Args:
        path (str): Path to the payload file

    Returns:
        tuple: (regular_payloads, time_payloads) where time_payloads is a
            dict mapping engine name (str) to a list of payload strings.
    """
    regular = []
    time_based = {}
    current_engine = None
    in_time_section = False

    with open(path, 'r', encoding='utf-8', errors='replace') as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            if line.startswith('# [time-based]'):
                in_time_section = True
                continue
            if line.startswith('#'):
                if in_time_section:
                    marker = line.lstrip('#').strip().strip('[]')
                    # Only treat "# [name]" style comments as engine groups.
                    if line.replace(' ', '').startswith('#['):
                        current_engine = marker
                        time_based.setdefault(current_engine, [])
                continue
            if in_time_section and current_engine:
                time_based[current_engine].append(line)
            else:
                regular.append(line)

    return regular, time_based


def _timed_request(method, url, data=None, timeout=30):
    """
    Issue one request and measure elapsed time.

    Returns:
        tuple: (elapsed_seconds, response_or_None). Network errors and
        timeouts return (None, None) instead of raising; callers must never
        treat those as a hit.
    """
    start = time.perf_counter()
    try:
        response = requests.request(
            method, url, data=data, headers=_headers(), timeout=timeout
        )
    except requests.Timeout:
        logger.warning("request timeout (not counted as hit): %s", url)
        return None, None
    except requests.RequestException as exc:
        logger.warning("network error (not counted as hit) %s: %s", url, exc)
        return None, None
    elapsed = time.perf_counter() - start
    return elapsed, response


def _measure_balance(method, url, data, samples, timeout):
    """
    Measure the baseline latency of the unmodified request.

    Returns:
        tuple: (median, threshold) or (None, None) when the baseline is too
        unstable or too many probes fail, in which case the point is skipped.
    """
    timings = []
    for _ in range(samples):
        elapsed, _resp = _timed_request(method, url, data=data, timeout=timeout)
        if elapsed is None:
            logger.warning("baseline probe failed, skipping point: %s", url)
            return None, None
        timings.append(elapsed)

    median = statistics.median(timings)
    spread = max(timings) - min(timings)
    logger.info(
        "baseline %s %s samples=%s timings=%s median=%.3fs spread=%.3fs",
        method, url, len(timings),
        ['%.3f' % t for t in timings], median, spread,
    )

    # Unstable baseline (jittery network / throttling) -> skip rather than
    # guess a threshold that would either false-positive or miss everything.
    # The absolute floor keeps sub-millisecond medians from being flagged by
    # trivial scheduling jitter.
    jitter_allowance = max(BASELINE_JITTER_FLOOR, median * BASELINE_JITTER_RATIO)
    if spread > jitter_allowance:
        logger.warning(
            "baseline unstable (spread=%.3fs > allowance=%.3fs), skipping point: %s",
            spread, jitter_allowance, url,
        )
        return None, None

    threshold = max(median + THRESHOLD_MARGIN, median * THRESHOLD_MULTIPLIER)
    logger.info("threshold %s: %.3fs (median=%.3fs)", url, threshold, median)
    return median, threshold


def time_based_scan(method, url, time_payloads, data=None, target_field=None,
                    baseline_samples=DEFAULT_BASELINE_SAMPLES,
                    request_timeout=30,
                    max_requests=DEFAULT_MAX_REQUESTS_PER_POINT,
                    time_budget=DEFAULT_TIME_BUDGET):
    """
    Run a conservative time-based blind injection check for one point.

    Flow per point:
      1. Probe the original request ``baseline_samples`` (3~5) times and take
         the median; skip the point on failed probes or unstable baselines.
      2. Derive threshold = max(median + fixed margin, median * multiplier).
      3. Send each payload once. A response slower than the threshold is only
         a *candidate*; network errors/timeouts never count.
      4. A candidate must be re-confirmed by CONFIRM_HITS consecutive slow
         responses before it is recorded.
      5. Hard caps: at most ``max_requests`` requests and ``time_budget``
         seconds for this point, whichever comes first.

    Args:
        method (str): 'GET' or 'POST'
        url (str): Target URL (payload already appended for GET)
        time_payloads (dict): engine -> payload list (from load_payloads)
        data (dict|None): Form fields for POST; the payload must already be
            placed in the target field.

    Returns:
        dict|None: Hit details (engine, payload, elapsed stats) or None.
    """
    if not 3 <= baseline_samples <= 5:
        baseline_samples = DEFAULT_BASELINE_SAMPLES

    deadline = time.perf_counter() + time_budget
    requests_sent = 0

    def budget_left():
        return requests_sent < max_requests and time.perf_counter() < deadline

    median, threshold = _measure_balance(
        method, url, data, baseline_samples, request_timeout
    )
    requests_sent += baseline_samples
    if median is None:
        return None

    for engine, payloads in time_payloads.items():
        for payload in payloads:
            if not budget_left():
                logger.warning(
                    "time-based budget exhausted for %s (requests=%s), stopping point",
                    url, requests_sent,
                )
                return None

            if method.upper() == 'POST':
                payload_data = dict(data) if data else {}
                if target_field is not None:
                    payload_data[target_field] = payload
                elapsed, _resp = _timed_request(
                    'POST', url, data=payload_data, timeout=request_timeout
                )
                point_label = "%s field=%s" % (url, target_field)
            else:
                elapsed, _resp = _timed_request(
                    'GET', url + payload, timeout=request_timeout
                )
                point_label = url + payload
            requests_sent += 1

            if elapsed is None:
                continue  # error/timeout is never a hit
            if elapsed < threshold:
                continue

            logger.info(
                "candidate slow response %.3fs > threshold %.3fs, entering retry: %s",
                elapsed, threshold, point_label,
            )

            confirmed = 1
            confirm_timings = [elapsed]
            while confirmed < CONFIRM_HITS and budget_left():
                logger.info(
                    "retry %d/%d for %s (%s)",
                    confirmed + 1, CONFIRM_HITS, point_label, engine,
                )
                if method.upper() == 'POST':
                    ret_elapsed, _ = _timed_request(
                        'POST', url, data=payload_data, timeout=request_timeout
                    )
                else:
                    ret_elapsed, _ = _timed_request(
                        'GET', url + payload, timeout=request_timeout
                    )
                requests_sent += 1
                if ret_elapsed is None:
                    logger.info("retry failed on network error, candidate dropped: %s",
                                point_label)
                    break
                if ret_elapsed < threshold:
                    logger.info(
                        "retry elapsed %.3fs under threshold %.3fs, candidate dropped: %s",
                        ret_elapsed, threshold, point_label,
                    )
                    break
                confirmed += 1
                confirm_timings.append(ret_elapsed)

            if confirmed >= CONFIRM_HITS:
                logger.info(
                    "CONFIRMED time-based injection engine=%s point=%s timings=%s",
                    engine, point_label, ['%.3f' % t for t in confirm_timings],
                )
                return {
                    'method': method.upper(),
                    'url': url,
                    'engine': engine,
                    'payload': payload,
                    'baseline_median': median,
                    'threshold': threshold,
                    'elapsed': confirm_timings,
                }
            logger.info("candidate not confirmed after retries: %s", point_label)

    return None
