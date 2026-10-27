"""Locations used by the library, the experiments and the tests.

Datasets are not part of the repository. Put the CICIDS2017 captures (and the caches built from them) in `data/`, or
point the environment variable NIDS_DATA at another folder.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, 'config')
RESULTS = os.path.join(ROOT, 'results')
DATA = os.path.abspath(os.environ.get('NIDS_DATA', os.path.join(ROOT, 'data')))
RULES = os.path.join(CONFIG, 'rules.yaml')
LEGACY_RULES = os.path.join(CONFIG, 'legacy_rules.yaml')
SYNTHETIC_PCAP = os.path.join(ROOT, 'tests', 'data', 'large_evaluation_dataset.pcap')
