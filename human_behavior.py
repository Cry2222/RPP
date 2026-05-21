import random
import time
import math
import logging

logger = logging.getLogger(__name__)


def _bezier_ease(t, p1x=0.25, p1y=0.1, p2x=0.75, p2y=0.9):
    lo, hi = 0.0, 1.0
    for _ in range(20):
        mid = (lo + hi) / 2
        x = 3 * (1 - mid) ** 2 * mid * p1x + 3 * (1 - mid) * mid ** 2 * p2x + mid ** 3
        if x < t:
            lo = mid
        else:
            hi = mid
    s = (lo + hi) / 2
    return 3 * (1 - s) ** 2 * s * p1y + 3 * (1 - s) * s ** 2 * p2y + s ** 3


def human_delay(min_s=2.1, max_s=5.8, label=None):
    base = random.uniform(min_s, max_s)
    jitter = random.gauss(0, (max_s - min_s) * 0.08)
    delay = max(min_s * 0.7, base + jitter)

    if random.random() < 0.12:
        delay += random.uniform(0.8, 2.5)

    if random.random() < 0.05:
        delay += random.uniform(2.0, 5.0)

    if label:
        logger.debug(f"[HB] {label}: {delay:.2f}s")
    time.sleep(delay)
    return delay


def reading_delay(content_length=0):
    if content_length > 50000:
        base = random.uniform(3.5, 7.0)
    elif content_length > 10000:
        base = random.uniform(2.5, 5.0)
    else:
        base = random.uniform(1.8, 3.5)

    scrolls = random.randint(1, 3)
    for _ in range(scrolls):
        scroll_pause = random.uniform(0.3, 1.2)
        base += scroll_pause

    if random.random() < 0.15:
        base += random.uniform(1.0, 3.0)

    logger.debug(f"[HB] reading: {base:.2f}s ({scrolls} scrolls, {content_length} chars)")
    time.sleep(base)
    return base


def typing_delay(field_length=16):
    wpm = random.uniform(45, 85)
    chars_per_sec = (wpm * 5) / 60

    total = field_length / chars_per_sec

    pauses = random.randint(0, max(1, field_length // 8))
    for _ in range(pauses):
        total += random.uniform(0.15, 0.6)

    total *= random.uniform(0.85, 1.15)

    total = max(0.5, min(total, 6.0))

    logger.debug(f"[HB] typing: {total:.2f}s ({field_length} chars, {wpm:.0f} wpm)")
    time.sleep(total)
    return total


def form_fill_delay():
    delay = random.uniform(1.2, 3.8)

    if random.random() < 0.2:
        delay += random.uniform(0.5, 2.0)

    logger.debug(f"[HB] form_fill: {delay:.2f}s")
    time.sleep(delay)
    return delay


def navigation_delay():
    delay = random.uniform(0.8, 2.5)
    delay += random.uniform(0.1, 0.5)

    logger.debug(f"[HB] nav: {delay:.2f}s")
    time.sleep(delay)
    return delay


def pre_submit_delay():
    think_time = random.uniform(1.5, 4.5)

    if random.random() < 0.1:
        think_time += random.uniform(2.0, 5.0)

    if random.random() < 0.08:
        review = random.uniform(0.5, 1.5)
        think_time += review

    logger.debug(f"[HB] pre_submit: {think_time:.2f}s")
    time.sleep(think_time)
    return think_time


def between_requests_delay():
    t = random.random()
    eased = _bezier_ease(t)
    delay = 2.1 + eased * (5.8 - 2.1)

    jitter = random.gauss(0, 0.3)
    delay = max(1.5, delay + jitter)

    logger.debug(f"[HB] between: {delay:.2f}s")
    time.sleep(delay)
    return delay


def page_interaction_delay(page_length=0):
    base = random.uniform(1.0, 2.5)

    if page_length > 30000:
        num_scrolls = random.randint(2, 5)
    elif page_length > 10000:
        num_scrolls = random.randint(1, 3)
    else:
        num_scrolls = random.randint(0, 2)

    for i in range(num_scrolls):
        speed = random.uniform(0.3, 1.0)
        pause = random.uniform(0.2, 0.8) if random.random() < 0.6 else 0
        base += speed + pause

    logger.debug(f"[HB] page_interact: {base:.2f}s ({num_scrolls} scrolls)")
    time.sleep(base)
    return base


def checkout_flow_delay(step="generic"):
    step_ranges = {
        "browse_site": (2.5, 6.0),
        "add_to_cart": (1.5, 4.0),
        "view_cart": (2.0, 5.0),
        "fill_address": (3.0, 7.0),
        "fill_payment": (2.5, 6.0),
        "review_order": (2.0, 5.0),
        "submit_payment": (1.5, 4.0),
        "generic": (2.1, 5.8),
    }

    min_s, max_s = step_ranges.get(step, step_ranges["generic"])
    delay = random.uniform(min_s, max_s)

    if random.random() < 0.1:
        delay += random.uniform(1.0, 3.0)

    delay *= random.uniform(0.9, 1.1)
    delay = max(min_s * 0.8, delay)

    logger.debug(f"[HB] checkout/{step}: {delay:.2f}s")
    time.sleep(delay)
    return delay


def retry_delay(attempt, base_min=3.0, base_max=8.0):
    delay = random.uniform(base_min, base_max) * (1.5 ** attempt)
    delay += random.gauss(0, delay * 0.1)
    delay = max(base_min, delay)

    logger.debug(f"[HB] retry #{attempt}: {delay:.2f}s")
    time.sleep(delay)
    return delay
