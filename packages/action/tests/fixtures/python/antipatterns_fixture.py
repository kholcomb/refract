"""
Synthetic Python fixtures to test anti-pattern detection.
This file intentionally contains anti-patterns — do not use in production.
"""

# ── Wildcard import ─────────────────────────────────────────────────────────
from os.path import *       # antipattern: wildcard_import
from sys import *           # antipattern: wildcard_import

import hashlib
import pickle
import subprocess


# ── Mutable default arguments ────────────────────────────────────────────────
def add_item(item, collection=[]):     # antipattern: mutable_default_argument
    collection.append(item)
    return collection


def build_config(name, options={}):   # antipattern: mutable_default_argument
    options['name'] = name
    return options


# ── Bare except / exception sink ─────────────────────────────────────────────
def load_data(filepath):
    try:
        with open(filepath) as f:
            return f.read()
    except:                            # antipattern: bare_except
        pass                           # antipattern: exception_sink


def parse_value(raw):
    try:
        return int(raw)
    except:                            # antipattern: bare_except
        return None


# ── Magic numbers ─────────────────────────────────────────────────────────────
def calculate_discount(price):
    if price > 999:                    # antipattern: magic_number (999)
        return price * 0.85            # antipattern: magic_number (0.85)
    elif price > 499:                  # antipattern: magic_number (499)
        return price * 0.92            # antipattern: magic_number (0.92)
    return price


# ── Deep nesting ──────────────────────────────────────────────────────────────
def process_orders(orders):
    results = []
    for order in orders:                                    # depth 1
        if order.get('active'):                             # depth 2
            for item in order.get('items', []):             # depth 3
                if item.get('available'):                   # depth 4
                    for variant in item.get('variants', []): # depth 5
                        if variant.get('stock') > 0:        # depth 6
                            for size in variant.get('sizes', []):  # depth 7
                                results.append(size)        # antipattern: deep_nesting
    return results


# ── N+1 query pattern ────────────────────────────────────────────────────────
def get_user_posts(users, db):
    all_posts = []
    for user in users:
        posts = db.query(Post).filter(user_id=user.id).all()  # antipattern: n_plus_one
        all_posts.extend(posts)
    return all_posts


# ── Long method (triggers lizard) ────────────────────────────────────────────
def mega_function(data):
    """This function does way too much."""
    step1 = data.get('step1')
    step2 = data.get('step2')
    step3 = data.get('step3')
    step4 = data.get('step4')
    step5 = data.get('step5')
    step6 = data.get('step6')
    step7 = data.get('step7')
    step8 = data.get('step8')
    step9 = data.get('step9')
    step10 = data.get('step10')
    result = {}

    if step1:
        result['a'] = step1 * 2
    if step2:
        result['b'] = step2 * 3
    if step3:
        result['c'] = step3 + step2 if step2 else step3
    if step4:
        result['d'] = [x for x in range(step4)]
    if step5:
        result['e'] = str(step5).upper()
    if step6:
        result['f'] = step6 / (step5 or 1)
    if step7:
        result['g'] = step7 ** 2
    if step8:
        result['h'] = list(reversed(str(step8)))
    if step9:
        result['i'] = step9 + step8 if step8 else step9
    if step10:
        result['j'] = step10 % 7
    # padding to hit line threshold...
    x1 = result.get('a', 0) + result.get('b', 0)
    x2 = result.get('c', 0) + result.get('d', [0])[0]
    x3 = result.get('e', '') + str(result.get('f', ''))
    x4 = result.get('g', 0) + result.get('h', [0])[0]
    x5 = x1 + x2 + x3.__len__() + x4
    final = {
        'combined': x5,
        'parts': result,
        'metadata': {
            'computed_at': 'now',
            'version': 42,           # antipattern: magic_number
        }
    }
    return final


# ── Hardcoded secret ─────────────────────────────────────────────────────────
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # antipattern: hardcoded_secret
DB_PASSWORD = "super_secret_password_123"                       # antipattern: hardcoded_secret


# ── Weak cryptography ────────────────────────────────────────────────────────
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # antipattern: weak_cryptography (bandit B303)


# ── Insecure deserialization ─────────────────────────────────────────────────
def load_session(data):
    return pickle.loads(data)  # antipattern: insecure_deserialization (bandit B301)


# ── Shell injection vector ───────────────────────────────────────────────────
def run_report(report_name):
    subprocess.call(f"generate_report {report_name}", shell=True)  # antipattern: shell_injection (bandit B602)
