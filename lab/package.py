"""Build importable per-snapshot ZIP files and one downloadable verification kit."""
import argparse
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'bundles')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    bundles = []
    for scenario in sorted((ROOT / 'scenarios').iterdir()):
        for version in ('before', 'after'):
            target = args.output / f'{scenario.name}-{version}.zip'
            with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as archive:
                for file in sorted((scenario / version).iterdir()):
                    archive.write(file, file.name)
            bundles.append(target)
    kit = args.output / 'netpolicy-validation-kit.zip'
    with zipfile.ZipFile(kit, 'w', zipfile.ZIP_DEFLATED) as archive:
        for file in bundles:
            archive.write(file, f'import/{file.name}')
        for file in (ROOT / 'scenarios').glob('*/expected.json'):
            archive.write(file, f'expectations/{file.parent.name}.json')
        for file in (ROOT / 'evidence/routeros').iterdir():
            archive.write(file, f'native-routeros/{file.name}')
        archive.write(ROOT / 'README.md', 'README.md')
    print(kit)


if __name__ == '__main__':
    main()
