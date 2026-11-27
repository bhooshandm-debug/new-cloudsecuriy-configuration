"""Thread-safe sliding-window rate limiter for the Flask application.

Tracks request timestamps per route name and client IP.
"""
from collections import defaultdict, deque
from functools import wraps
from threading import Lock
from time import monotonic

from flask import current_app, jsonify, request

_events = defaultdict(deque)
_lock = Lock()


def limit(name, maximum, window_seconds, methods=None):
    """Limit a route by its configured name and client IP; reject with 429."""
    def decorate(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if current_app.testing:
                return view(*args, **kwargs)
            if methods is not None:
                if request.method not in methods:
                    return view(*args, **kwargs)
            elif request.method in ("GET", "HEAD", "OPTIONS"):
                return view(*args, **kwargs)

            now = monotonic()
            ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "unknown"
            key = (name, ip)
            with _lock:
                events = _events[key]
                cutoff = now - window_seconds
                while events and events[0] <= cutoff:
                    events.popleft()
                if len(events) >= maximum:
                    retry_after = max(1, int(window_seconds - (now - events[0])))
                    response = jsonify(error="Too many requests. Try again later.")
                    response.status_code = 429
                    response.headers["Retry-After"] = str(retry_after)
                    return response
                events.append(now)
                # Expire inactive buckets and cap bookkeeping for long-lived processes.
                if len(_events) > 10000:
                    for old_key in list(_events)[:5000]:
                        old = _events[old_key]
                        while old and old[0] <= now - window_seconds:
                            old.popleft()
                        if not old:
                            _events.pop(old_key, None)
            return view(*args, **kwargs)
        return wrapped
    return decorate
