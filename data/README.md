# data/

Datasets are **not** included in the repository. Put them here (this folder is ignored by git except this file), or
keep them anywhere and set the environment variable `NIDS_DATA` to that folder.

## CICIDS2017 raw captures

1. Open the official dataset page of the Canadian Institute for Cybersecurity:
   <https://www.unb.ca/cic/datasets/ids-2017.html> → "Download this dataset". Follow the dataset's terms; CIC asks
   users to cite Sharafaldin et al., ICISSP 2018.
2. From the `PCAPs` folder download `Friday-WorkingHours.pcap` and `Wednesday-workingHours.pcap`.
3. Place them here:

```
data/Friday-WorkingHours.pcap        8,839,309,056 bytes   MD5 7366c552425956e610bd69f57feb7e7a
data/Wednesday-workingHours.pcap    13,420,789,612 bytes   MD5 a8c9cd0ea22e3df6acc1c5972f38f0bf
```
(MD5 of the files used for the paper; check with `md5 -q <file>` on macOS or `md5sum <file>` on Linux.)

The first run builds a compact cache next to each capture (`friday.cache`, `wednesday.cache`, a few hundred MB) and
uses it afterwards. You can also build it yourself: `python -m nids.pcapng_reader data/Friday-WorkingHours.pcap
data/friday.cache`.

## Baseline outputs

`baselines/zeek/run_zeek.sh` and `baselines/suricata/run_suricata.sh` write their raw outputs to
`data/zeek/out_*/` and `data/suricata/out_*/`; the scoring scripts read them from there. The scored results are kept
in `results/`.

No dataset is needed for the tests or the demo: they use the small synthetic capture in `tests/data/`.
