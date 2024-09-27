# Building binaries
install pyinstaller
```
poetry add --dev pyinstaller

```
Creating an executable
```
poetry run pyinstaller --onefile your_project_name.py

```
Had to adjust the `pyproject.toml` file
```
[tool.poetry.dependencies]
python = "<3.14,>=3.8.1"
```
Run the commands within your project directory, the final binaries will appear in `dist`

One of the modules was missing, so had to specify files to add, see below. Please adjust for your own virtual environment.

for mac
```
poetry run pyinstaller --onefile --add-data "/Users/trbouma/Library/Caches/pypoetry/virtualenvs/safebox-32NsP7gP-py3.12/lib/python3.12/site-packages/coolname/data/*:coolname/data" --name safebox ./safebox/cli.py
```
for ubuntu
```
 poetry run pyinstaller --onefile --add-data "/home/trbouma/.cache/pypoetry/virtualenvs/bintest-7_VnywOr-py3.10/lib/python3.10/site-packages/coolname/data/*:coolname/data" --name safebox ./safebox/cli.py

```