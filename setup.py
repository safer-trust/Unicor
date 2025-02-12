from setuptools import setup, find_packages

setup(
    name="unicor",
    version="0.1",
    package_dir={"": "src"},  # Explicitly tell setuptools that packages are in src/
    packages=find_packages(where="src"),  # Find packages inside src/
    install_requires=[],
    entry_points={
        "console_scripts": [
            "unicor=unicor:main"  # Ensure `main()` exists in unicorcli.py
        ],
    },
)

