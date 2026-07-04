# Garudatva ML Training Datasets

## Required Files

Place the following NumPy files in this directory before running `trainer.py`:

| File | Description | Samples |
|---|---|---|
| `amd_features.npy` | AMD dataset feature matrix (99 features) | 24,650 |
| `amd_labels.npy` | AMD labels (0=benign, 1=malware) | 24,650 |
| `cic_features.npy` | CIC-AndMal2017 feature matrix | 10,854 |
| `cic_labels.npy` | CIC-AndMal2017 labels | 10,854 |
| `drebin_features.npy` | Drebin feature matrix | 129,013 |
| `drebin_labels.npy` | Drebin labels (5,560 malware + 123,453 benign) | 129,013 |

## Download Sources

- **AMD**: https://amd.arguslab.org — Request access, download APKs, extract features using `feature_extractor.py`
- **CIC-AndMal2017**: https://www.unb.ca/cic/datasets/andmal2017.html — Direct download available
- **Drebin**: https://www.sec.cs.tu-bs.de/~danarp/drebin/ — Request access form

## Feature Extraction

After downloading raw APKs, extract features using:
```bash
python backend/ml/feature_extractor.py --dataset amd --input /path/to/apks --output ml/datasets/
```

## Training

Once all `.npy` files are in place:
```bash
python backend/ml/trainer.py
```

Output: `ml/models/india_malware_rf.pkl` and `ml/models/feature_indices.pkl`

Expected AUC: 0.972

## Feature Vector (99 total → top 87 selected by Information Gain)

See `core/static/ml_classifier.py` → `FEATURE_NAMES` for the complete ordered list.